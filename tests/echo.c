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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "../src/tlssock.h"

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <assert.h>
#include <getopt.h>
#include <limits.h>
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

static const char *psku = NULL;
static const char *pskk = NULL;
static const char *sopts = "T:u:k:";
static const struct option lopts[] = {
  { "tcp", required_argument, .val = 'T' },
  { "user", required_argument, .val = 'u' },
  { "key", required_argument, .val = 'k' },
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

static uint8_t
hex2low(uint8_t c)
{
  static uint8_t table[UINT8_MAX] = {
    ['0'] = 1, ['1'] = 2, ['2'] = 3, ['3'] = 4, ['4'] = 5,
    ['5'] = 6, ['6'] = 7, ['7'] = 8, ['8'] = 9, ['9'] = 10,
    ['A'] = 11, ['B'] = 12, ['C'] = 13, ['D'] = 14, ['E'] = 15, ['F'] = 16,
    ['a'] = 11, ['b'] = 12, ['c'] = 13, ['d'] = 14, ['e'] = 15, ['f'] = 16,
  };

  return table[c] - 1;
}

static bool
hex2bin(const char *hex, uint8_t *bin, size_t len)
{
  if (strlen(hex) != len * 2)
    return false;

  for (size_t i = 0; i < len * 2; i += 2) {
    uint8_t h = hex2low(hex[i]);
    uint8_t l = hex2low(hex[i + 1]);

    if (h == UINT8_MAX || l == UINT8_MAX)
      return false;

    if (bin)
      bin[i / 2] = h << 4 | l;
  }

  return true;
}

static ssize_t
keydup(uint8_t **key)
{
  size_t size = strlen(pskk) / 2;

  *key = malloc(size);
  assert(*key);
  assert(hex2bin(pskk, *key, size));

  return size;
}

static ssize_t
srv_cb(void *misc, const char *username, uint8_t **key)
{
  int *m = misc;

  assert(m);
  assert(key);
  assert(*m == 17);
  assert(username);
  assert(strcmp(username, psku) == 0);

  return keydup(key);
}

static ssize_t
clt_cb(void *misc, char **username, uint8_t **key)
{
  int *m = misc;

  assert(*m == 17);

  if (!psku || !pskk)
    return -1;

  *username = strdup(psku);
  assert(*username);

  return keydup(key);
}

int
main(int argc, char *argv[])
{
  char buffer[1024] = {};
  sockaddr_t addr = {};
  int misc = 17;
  int fd = -1;
  pid_t pid;

  srand(getpid());

  for (int c; (c = getopt_long(argc, argv, sopts, lopts, NULL)) >= 0; ) {
    switch (c) {
    case 'T':
      if (inet_pton(AF_INET, optarg, &addr.in.sin_addr) == 0) {
        addr.in.sin_port = htons(rand() % (INT16_MAX - 1024) + 1024);
        addr.in.sin_family = AF_INET;
        break;
      }

      if (inet_pton(AF_INET6, optarg, &addr.in6.sin6_addr) == 0) {
        addr.in6.sin6_port = htons(rand() % (INT16_MAX - 1024) + 1024);
        addr.in6.sin6_family = AF_INET6;
        break;
      }

      fprintf(stderr, "Invalid IP address: %s!\n", optarg);
      goto usage;

    case 'u':
      psku = optarg;
      break;

    case 'k':
      pskk = optarg;

      if (!hex2bin(pskk, NULL, strlen(pskk) / 2)) {
        fprintf(stderr, "Invalid PSK key!\n");
        goto usage;
      }

      break;

    default:
      fprintf(stderr, "Unknown option: %c!\n", c);
      goto usage;
    }
  }

  if (addr.addr.sa_family == 0) {
    fprintf(stderr, "Address not specified!\n");
    goto usage;
  }

  fd = socket(addr.addr.sa_family, SOCK_STREAM, IPPROTO_TLS);
  assert(fd >= 0);

  assert(bind(fd, &addr.addr, addrlen(&addr)) == 0);

  assert(listen(fd, 999) == 0);

  pid = fork();
  assert(pid >= 0);
  if (pid == 0) {
    tls_clt_handshake_t clt = { .misc = &misc };
    assert(close(fd) == 0);

    fd = socket(addr.addr.sa_family, SOCK_STREAM, IPPROTO_TLS);
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

  return 0;

usage:
  fprintf(stderr, "%s [-u USER -k KEY] -T HOST\n", argv[0]);
  return -1;
}

