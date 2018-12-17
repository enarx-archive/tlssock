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

#include "../src/tlssock.h"

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>
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

static socklen_t
addrlen(sockaddr_t *addr)
{
  switch (addr->addr.sa_family) {
  case AF_INET6: return sizeof(addr->in6);
  case AF_INET: return sizeof(addr->in);
  default: return 0;
  }
}

static ssize_t
srv_cb(void *misc, const char *username, uint8_t **key)
{
  int *m = misc;

  assert(*m == 17);

  if (!psku || !pskk)
    return -1;

  if (strcmp(username, psku) != 0)
    return -1;

  *key = (uint8_t *) strdup(pskk);
  assert(*key);
  return strlen(pskk);
}

static ssize_t
clt_cb(void *misc, char **username, uint8_t **key)
{
  int *m = misc;

  assert(*m == 17);

  if (!psku || !pskk)
    return -1;

  *username = strdup(psku);
  *key = (uint8_t *) strdup(pskk);

  assert(*username);
  assert(*key);

  return strlen(pskk);
}

int
main(int argc, char *argv[])
{
  int type = SOCK_STREAM;
  char buffer[1024] = {};
  sockaddr_t addr = {};
  int misc = 17;
  int fd = -1;
  pid_t pid;

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

  if (optind != argc - 1)
    goto usage;

  srand(getpid());
  if (inet_pton(AF_INET, argv[optind], &addr.in.sin_addr) == 0) {
    addr.in.sin_port = htons(rand() % (INT16_MAX - 1024) + 1024);
    addr.in.sin_family = AF_INET;
  } else if (inet_pton(AF_INET6, argv[optind], &addr.in6.sin6_addr) == 0) {
    addr.in6.sin6_port = htons(rand() % (INT16_MAX - 1024) + 1024);
    addr.in6.sin6_family = AF_INET6;
  } else {
    fprintf(stderr, "Invalid IP address!\n");
    goto usage;
  }

  fd = socket(addr.addr.sa_family, type, IPPROTO_TLS);
  assert(fd >= 0);

  assert(bind(fd, &addr.addr, addrlen(&addr)) == 0);

  assert(listen(fd, 999) == 0);

  pid = fork();
  assert(pid >= 0);
  if (pid == 0) {
    tls_clt_handshake_t clt = { .misc = &misc };
    assert(close(fd) == 0);

    fd = socket(addr.addr.sa_family, type, IPPROTO_TLS);
    assert(fd >= 0);

    assert(connect(fd, &addr.addr, addrlen(&addr)) == 0);

    if (psku && pskk) {
      clt.psk = clt_cb;
    } else {
      fprintf(stderr, "No authentication method specified!\n");
      goto usage;
    }

    if (setsockopt(fd, IPPROTO_TLS, TLS_CLT_HANDSHAKE, &clt, sizeof(clt)) != 0) {
      fprintf(stderr, "client: %d: %m\n", errno);
      abort();
    }

    assert(send(fd, "foo", 3, 0) == 3);

    assert(recv(fd, buffer, sizeof(buffer), 0) == 3);

    assert(memcmp(buffer, "foo", 3) == 0);

    assert(close(fd) == 0);

    free(psku);
    return 0;
  }

  tls_srv_handshake_t srv = { .misc = &misc };

  int tmp = accept(fd, NULL, NULL);
  assert(tmp >= 0);
  assert(close(fd) == 0);
  fd = tmp;

  if (psku && pskk) {
    srv.psk = srv_cb;
  } else {
    fprintf(stderr, "No authentication method specified!\n");
    goto usage;
  }

  if (setsockopt(fd, IPPROTO_TLS, TLS_SRV_HANDSHAKE, &srv, sizeof(srv)) != 0) {
    fprintf(stderr, "server: %d: %m\n", errno);
    abort();
  }

  ssize_t len = recv(fd, buffer, sizeof(buffer), 0);
  assert(len >= 0);
  assert(send(fd, buffer, len, 0) == len);

  assert(close(fd) == 0);
  assert(waitpid(pid, &tmp, 0) == pid);
  assert(WEXITSTATUS(tmp) == 0);

  free(psku);
  return 0;

usage:
  fprintf(stderr, "%s [-d] [-p USER:KEY] HOST\n", argv[0]);
  free(psku);
  return -1;
}

