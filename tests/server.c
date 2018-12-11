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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "../tlssock.h"

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <inttypes.h>
#include <stdbool.h>
#include <assert.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>

typedef union {
    struct sockaddr_in6 in6;
    struct sockaddr_in in;
    struct sockaddr addr;
} sockaddr_t;

static char *psku = NULL;
static char *pskk = NULL;
static const char *sopts = "dp:";
static const struct option lopts[] = {
  { "datagram", no_argument, .val = 'd' },
  { "psk", required_argument, .val = 'p' },
  {}
};

static bool
parse_port(const char *string, in_port_t *number)
{
  uintmax_t port;

  port = strtoumax(string, NULL, 10);
  if (port == UINTMAX_MAX && errno == ERANGE)
    return false;

  if (port > UINT16_MAX)
    return false;

  *number = port;
  return true;
}

static socklen_t
addrlen(sockaddr_t *addr)
{
  switch (addr->addr.sa_family) {
  case AF_INET6: return sizeof(addr->in6);
  case AF_INET: return sizeof(addr->in);
  default: return 0;
  }
}

static int
srv_cb(tls_opt_psk_srv_t *srv, void *misc, const char *username,
       int (*callback)(tls_opt_psk_srv_t *srv,
                       const uint8_t *key, size_t keylen))
{
  int *m = misc;

  fprintf(stderr, "Username: %s\n", username);

  assert(*m == 17);

  if (strcmp(username, psku) != 0)
    return -1;

  return callback(srv, (void *) pskk, strlen(pskk));
}

int
main(int argc, char *argv[])
{
  int type = SOCK_STREAM;
  char buffer[1024] = {};
  sockaddr_t addr = {};
  char *str = NULL;
  int misc = 17;
  int fd = -1;
  pid_t pid;

  str = strstr(argv[0], "server");
  if (!str || strlen(str) != strlen("server")) {
    fprintf(stderr, "Invalid executable name!\n");
    return 1;
  }

  for (int c; (c = getopt_long(argc, argv, sopts, lopts, NULL)) >= 0; ) {
    switch (c) {
    case 'd':
      type = SOCK_DGRAM;
      break;

    case 'p':
      free(psku);

      psku = strdup(optarg);
      assert(psku);

      pskk = strchr(psku, ':');
      if (!pskk) {
        fprintf(stderr, "Invalid PSK argument!\n");
        goto usage;
      }

      *pskk++ = 0;

      switch (strlen(pskk)) {
      case 16: break;
      case 32: break;
      default:
        fprintf(stderr, "Invalid PSK key!\n");
        goto usage;
      }

      break;

    default:
      fprintf(stderr, "Unknown option: %c!\n", c);
      goto usage;
    }
  }

  if (optind != argc - 2)
    goto usage;

  if (inet_pton(AF_INET, argv[optind], &addr.in.sin_addr) == 0) {
    if (!parse_port(argv[optind+1], &addr.in.sin_port)) {
      fprintf(stderr, "Invalid port: %s!\n", argv[optind+1]);
      goto usage;
    }

    addr.in.sin_family = AF_INET;
  } else if (inet_pton(AF_INET6, argv[optind], &addr.in6.sin6_addr) == 0) {
    if (!parse_port(argv[optind+1], &addr.in6.sin6_port)) {
      fprintf(stderr, "Invalid port: %s!\n", argv[optind+1]);
      goto usage;
    }

    addr.in6.sin6_family = AF_INET;
  } else {
    fprintf(stderr, "Invalid IP address!\n");
    goto usage;
  }

  fd = socket(addr.addr.sa_family, type | SOCK_CLOEXEC, IPPROTO_TLS_SRV);
  assert(fd >= 0);

  assert(bind(fd, &addr.addr, addrlen(&addr)) == 0);

  assert(listen(fd, 999) == 0);

  pid = fork();
  assert(pid >= 0);
  if (pid == 0) {
    char *const env[] = { NULL };
    strcpy(str, "client");
    execve(argv[0], argv, env);
    return 1;
  }

  int tmp = accept(fd, NULL, NULL);
  assert(tmp >= 0);
  assert(close(fd) == 0);
  fd = tmp;

  assert(setsockopt(fd, IPPROTO_TLS_SRV, TLS_OPT_MISC,
                    &misc, sizeof(misc)) == 0);

  if (psku && pskk) {
    assert(setsockopt(fd, IPPROTO_TLS_SRV, TLS_OPT_PSK, &srv_cb, 0) == 0);
  } else {
    fprintf(stderr, "No authentication method specified!\n");
    goto usage;
  }

  assert(setsockopt(fd, IPPROTO_TLS_SRV, TLS_OPT_HANDSHAKE, NULL, 0) == 0);

  ssize_t len = recv(fd, buffer, sizeof(buffer), 0);
  assert(len >= 0);
  assert(send(fd, buffer, len, 0) == len);

  assert(close(fd) == 0);
  assert(waitpid(pid, &tmp, 0) == 0);
  assert(WEXITSTATUS(tmp) == 0);

  free(psku);
  return 0;

usage:
  fprintf(stderr, "%s [-d] [-p USER:KEY] HOST PORT\n", argv[0]);
  free(psku);
  return -1;
}

