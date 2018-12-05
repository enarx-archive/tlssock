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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

static in_port_t
rport(void)
{
  static const in_port_t max = UINT16_MAX;
  static const in_port_t min = 1024;
  return htons(rand() % (max - min) + min);
}

static void
test_errno(int expected)
{
  if (errno != expected) {
    fprintf(stderr, "expected: %d: %s\n", expected, strerror(expected));
    fprintf(stderr, "received: %d: %m\n", errno);
    _exit(1);
  }
}

typedef union {
    struct sockaddr_in6 in6;
    struct sockaddr_in in;
    struct sockaddr addr;
} sockaddr_t;

static void
test(int type, const struct sockaddr *addr, socklen_t addrlen)
{
  int fd;

  fd = socket(addr->sa_family, type, 0);
  assert(fd >= 0);

  assert(bind(fd, addr, addrlen) == 0);
  assert(bind(fd, addr, addrlen) == -1);
  test_errno(EINVAL);

  close(fd);
}

int
main(int argc, const char *argv[])
{
  sockaddr_t in6 = { .in6 = { AF_INET6, rport(), .sin6_addr = IN6ADDR_LOOPBACK_INIT } };
  sockaddr_t in = { .in = { AF_INET, rport(), { htonl(INADDR_LOOPBACK) } } };
  test(SOCK_STREAM, &in.addr, sizeof(in.in));
  test(SOCK_DGRAM, &in.addr, sizeof(in.in));
  test(SOCK_STREAM, &in6.addr, sizeof(in6.in6));
  test(SOCK_DGRAM, &in6.addr, sizeof(in6.in6));
}
