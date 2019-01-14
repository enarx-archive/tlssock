/* vim: set tabstop=8 shiftwidth=2 softtabstop=2 expandtab smarttab colorcolumn=80: */
/*
 * Copyright 2018 Red Hat, Inc.
 *
 * Author: Nathaniel McCallum
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "../lib/tlssock.h"
#include "opt.h"
#include "hex.h"
#include "exe.h"
#include "non.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <poll.h>

#define addrinfo_auto_t addrinfo_t __attribute__((cleanup(addrinfo_cleanup)))
#define fd_auto_t fd_t __attribute__((cleanup(fd_cleanup)))

typedef struct addrinfo addrinfo_t;
typedef int fd_t;

typedef enum {
  STATUS_SUCCESS = EXIT_SUCCESS,
  STATUS_FAILURE = EXIT_FAILURE,
  STATUS_CONTINUE,
} status_t;

static void
addrinfo_cleanup(addrinfo_t **ai)
{
  if (!ai || !*ai)
    return;

  freeaddrinfo(*ai);
}

static void
fd_cleanup(fd_t *fd)
{
  if (!fd || *fd < 0)
    return;

  close(*fd);
}

static bool
ai_family_applicable(const options_t *opts, const struct addrinfo *ai)
{
  switch (ai->ai_family) {
  case AF_INET6: return !opts->ipv4 || opts->ipv6;
  case AF_INET: return opts->ipv4 || !opts->ipv6;
  default: return false;
  }
}

static bool
ai_socktype_applicable(const options_t *opts, const struct addrinfo *ai)
{
  switch (ai->ai_socktype) {
  case SOCK_STREAM: return !opts->udp;
  case SOCK_DGRAM: return opts->udp;
  default: return false;
  }
}

static bool
ai_protocol_applicable(const options_t *opts, const struct addrinfo *ai)
{
  switch (ai->ai_protocol) {
  case IPPROTO_IP: return true;
  case IPPROTO_TCP: return !opts->udp;
  case IPPROTO_UDP: return opts->udp;
  default: return false;
  }
}

static bool
ai_applicable(const options_t *opts, const struct addrinfo *ai)
{
  return ai_family_applicable(opts, ai)
      && ai_socktype_applicable(opts, ai)
      && ai_protocol_applicable(opts, ai);
}

static ssize_t
keydup(const options_t *o, uint8_t **key)
{
  size_t size = strlen(o->pskk) / 2;

  *key = malloc(size);
  if (!*key)
    return -1;

  if (!hex2bin(o->pskk, *key, size))
    return -1;

  return size;
}

static ssize_t
srv_psk_cb(void *m, const char *username, uint8_t **key)
{
  const options_t *o = m;

  if (strcmp(username, o->psku) != 0)
    return -1;

  return keydup(o, key);
}

static ssize_t
clt_psk_cb(void *m, char **username, uint8_t **key)
{
  const options_t *o = m;

  *username = strdup(o->psku);
  if (!*username)
    return -1;

  return keydup(o, key);
}

static status_t
on_conn(options_t *opts, int con, int in, int out, const struct addrinfo *ai)
{
  int outs[] = { out, con };
  struct pollfd pfds[] = {
    { .fd = in, .events = POLLIN },
    { .fd = con, .events = POLLIN },
  };

  if (ai->ai_protocol == IPPROTO_TLS) {
    int ret;

    if (opts->listen) {
      tls_srv_handshake_t srv = { .misc = opts };

      if (opts->psku)
        srv.psk = srv_psk_cb;

      ret = non_setsockopt(con, IPPROTO_TLS,
                           TLS_SRV_HANDSHAKE, &srv, sizeof(srv));
    } else {
      tls_clt_handshake_t clt = { .misc = opts };

      if (opts->psku)
        clt.psk = clt_psk_cb;

      ret = non_setsockopt(con, IPPROTO_TLS,
                           TLS_CLT_HANDSHAKE, &clt, sizeof(clt));
    }

    if (ret != 0) {
      fprintf(stderr, "%m: Unable to complete TLS handshake!\n");
      shutdown(con, SHUT_RDWR);
      return STATUS_FAILURE;
    }
  }

  while (poll(pfds, 2, -1) >= 0) {
    char buffer[64 * 1024] = {};
    ssize_t ret;

    for (int i = 0; i < 2; i++) {
      if (!pfds[i].revents)
        continue;

      ret = read(pfds[i].fd, buffer, sizeof(buffer));
      if (ret <= 0) {
        if (pfds[i].revents != POLLHUP &&
            (errno == EAGAIN || errno == EWOULDBLOCK))
          continue;

        shutdown(con, SHUT_RDWR);

        if (ret == 0)
          return STATUS_SUCCESS;

        if (errno == 0 || (opts->listen && errno == EIO))
          return STATUS_SUCCESS;

        return STATUS_FAILURE;
      }

      if (non_write(outs[(i + 1) % 2], buffer, ret) != ret) {
        fprintf(stderr, "%m: Error during write()!\n");
        shutdown(con, SHUT_RDWR);
        return STATUS_FAILURE;
      }
    }
  }

  fprintf(stderr, "%m: Error during poll()!\n");
  shutdown(con, SHUT_RDWR);
  return STATUS_FAILURE;
}

static status_t
on_sock(options_t *opts, int fd, const struct addrinfo *ai)
{
  int out = STDOUT_FILENO;
  exe_auto_t *exe = NULL;
  int in = STDIN_FILENO;
  fd_auto_t con = -1;

  if (opts->exec) {
    exe = exe_run(opts->exec, opts->shell, ai->ai_socktype);
    if (!exe) {
      fprintf(stderr, "%m: error executing '%s'!\n", opts->exec);
      return STATUS_FAILURE;
    }

    in = out = exe_fd(exe);
  }

  if (opts->listen) {
    if (bind(fd, ai->ai_addr, ai->ai_addrlen) != 0)
      return STATUS_CONTINUE;

    if (listen(fd, 0) != 0)
      return STATUS_CONTINUE;

    con = non_accept(fd, NULL, NULL);
    if (con < 0)
      return STATUS_CONTINUE;

    shutdown(fd, SHUT_RDWR);
  } else if (non_connect(fd, ai->ai_addr, ai->ai_addrlen) != 0) {
    return STATUS_CONTINUE;
  }

  return on_conn(opts, opts->listen ? con : fd, in, out, ai);
}

int
main(int argc, char *argv[])
{
  addrinfo_auto_t *ai = NULL;
  options_t opts = {};

  signal(SIGPIPE, SIG_IGN);

  if (!opts_parse(&opts, argc, argv))
    return EXIT_FAILURE;

  if (getaddrinfo(opts.host, opts.port, NULL, &ai) != 0) {
    fprintf(stderr, "Invalid host (%s) or port (%s)!", opts.host, opts.port);
    return EXIT_FAILURE;
  }

  for (struct addrinfo *i = ai; i; i = i->ai_next) {
    int flags = SOCK_CLOEXEC | opts.block ? 0 : SOCK_NONBLOCK;
    fd_auto_t fd = -1;

    if (opts.tls) {
      if (!ai_applicable(&opts, i))
        continue;
      i->ai_protocol = IPPROTO_TLS;
    }

    fd = socket(i->ai_family, i->ai_socktype | flags, i->ai_protocol);
    if (fd < 0)
      continue;

    switch(on_sock(&opts, fd, i)) {
    case STATUS_SUCCESS: return EXIT_SUCCESS;
    case STATUS_FAILURE: return EXIT_FAILURE;
    case STATUS_CONTINUE: continue;
    }
  }

  fprintf(stderr, "No valid configuration!\n");
  return EXIT_FAILURE;
}
