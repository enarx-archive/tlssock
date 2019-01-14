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

#include "non.h"

#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>

int
non_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
  struct pollfd pfd = { .fd = sockfd, .events = POLLIN };
  int fd;

  fd = accept(sockfd, addr, addrlen);
  if (fd >= 0)
    return fd;

  if (errno != EAGAIN && errno != EWOULDBLOCK)
    return -1;

  if (poll(&pfd, 1, -1) == -1)
    return -1;

  return non_accept(sockfd, addr, addrlen);
}

int
non_connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
  struct pollfd pfd = { .fd = fd, .events = POLLOUT };
  socklen_t len = sizeof(errno);

  if (connect(fd, addr, addrlen) == 0)
    return 0;

  if (errno == EAGAIN || errno == EWOULDBLOCK)
    return non_connect(fd, addr, addrlen);

  if (errno != EINPROGRESS)
    return -1;

  if (poll(&pfd, 1, -1) == -1)
    return -1;

  if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &errno, &len) == -1)
    return -1;

  if (len != sizeof(errno)) {
    errno = EINVAL;
    return -1;
  }

  return errno == 0 ? 0 : -1;
}

int
non_setsockopt(int fd, int level, int name, const void *val, socklen_t len)
{
  struct pollfd pfd = { .fd = fd, .events = POLLIN };

  if (setsockopt(fd, level, name, val, len) == 0)
    return 0;

  if (errno != EAGAIN && errno != EWOULDBLOCK)
    return -1;

  if (poll(&pfd, 1, -1) == -1)
    return -1;

  return non_setsockopt(fd, level, name, val, len);
}

ssize_t
non_write(int fd, void *buf, size_t len)
{
  struct pollfd pfd = { .fd = fd, .events = POLLOUT };
  uint8_t *b = buf;
  ssize_t ret;

  ret = write(fd, buf, len);
  if (ret < 0) {
    if (errno != EAGAIN)
      return ret;

    ret = 0;
  } else if ((size_t) ret == len) {
    return ret;
  }

  if (poll(&pfd, 1, -1) == -1)
    return -1;

  return non_write(fd, &b[ret], len - ret);
}
