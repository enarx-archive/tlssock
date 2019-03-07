/* vim: set tabstop=8 shiftwidth=2 softtabstop=2 expandtab smarttab colorcolumn=80: */
/*
 * Copyright 2019 Red Hat, Inc.
 *
 * Author: Robbie Harwood
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

#include "gss.h"

#include "core.h"
#include "idx.h"
#include "gss-internal.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

static idx_t idx = {
  .rwl = PTHREAD_RWLOCK_INITIALIZER,
  .incref = (ref_cb_fn) &gss_incref,
  .decref = (ref_cb_fn) &gss_decref,
};

static void __attribute__((destructor))
destructor(void)
{
  idx_destroy(&idx);
}

int
accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
  return accept4(sockfd, addr, addrlen, 0);
}

int
accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
  gss_auto_t *listener = NULL, *new = NULL;
  int fd;

  /* flags can only be SOCK_NONBLOCK or SOCK_CLOEXEC, which are both fine. */

  fd = NEXT(accept4)(sockfd, addr, addrlen, flags);
  if (fd < 0)
    return fd;

  listener = idx_get(&idx, sockfd);
  if (!listener)
    return fd;

  new = gss_new();
  if (!new) {
    close(fd);
    return -1;
  }

  if (idx_set(&idx, fd, new, NULL))
    return fd;

  close(fd);
  return -1;
}

int
close(int fd)
{
  idx_del(&idx, fd);
  return NEXT(close)(fd);
}

/* Making the dup family work would require some way to share internal state -
 * doable, but nontrivial. */
int
dup(int oldfd)
{
  gss_auto_t *gss = idx_get(&idx, oldfd);
  if (!gss)
    return NEXT(dup)(oldfd);

  errno = ENOTSUP;
  return -1;
}

int
dup2(int oldfd, int newfd)
{
  gss_auto_t *gss = idx_get(&idx, oldfd);
  if (!gss)
    return NEXT(dup2)(oldfd, newfd);

  errno = ENOTSUP;
  return -1;
}

FILE *
fdopen(int fd, const char *mode)
{
  gss_auto_t *gss = idx_get(&idx, fd);
  if (!gss)
    return NEXT(fdopen)(fd, mode);

  /* Supporting this family should be doable without serious trickery for
   * GSSAPI. */
  errno = ENOTSUP;
  return NULL;
}

int
getsockopt(int sockfd, int level, int optname, void *optval,
           socklen_t *optlen)
{
  gss_auto_t *gss = NULL;

  if (level != IPPROTO_GSS)
    return NEXT(getsockopt)(sockfd, level, optname, optval, optlen);

  gss = idx_get(&idx, sockfd);
  if (!gss) /* uhhh... */
    return NEXT(getsockopt)(sockfd, level, optname, optval, optlen);

  return gss_getsockopt(gss, sockfd, optname, optval, optlen);
}

ssize_t
read(int fd, void *buf, size_t count)
{
  gss_auto_t *gss = idx_get(&idx, fd);
  if (!gss)
    return NEXT(read)(fd, buf, count);

  return gss_recv(gss, fd, buf, count);
}

ssize_t
recv(int sockfd, void *buf, size_t len, int flags)
{
  gss_auto_t *gss = idx_get(&idx, sockfd);
  if (!gss)
    return NEXT(recv)(sockfd, buf, len, flags);

  if (flags != 0) {
    errno = ENOSYS; /* TODO */
    return -1;
  }

  return gss_recv(gss, sockfd, buf, len);
}

ssize_t
recvfrom(int sockfd, void *buf, size_t len, int flags,
         struct sockaddr *src_addr, socklen_t *addrlen)
{
  gss_auto_t *gss = idx_get(&idx, sockfd);
  if (!gss)
    return NEXT(recvfrom)(sockfd, buf, len, flags, src_addr, addrlen);

  if (flags || src_addr) {
    errno = ENOSYS; /* TODO */
    return -1;
  }

  return gss_recv(gss, sockfd, buf, len);
}

ssize_t
recvmsg(int sockfd, struct msghdr *msg, int flags)
{
  gss_auto_t *gss = idx_get(&idx, sockfd);
  if (!gss)
    return NEXT(recvmsg)(sockfd, msg, flags);

  errno = ENOSYS; /* TODO */
  return -1;
}

ssize_t
send(int sockfd, const void *buf, size_t len, int flags)
{
  gss_auto_t *gss = idx_get(&idx, sockfd);
  if (!gss)
    return NEXT(send)(sockfd, buf, len, flags);

  if (flags) {
    errno = ENOSYS; /* TODO */
    return -1;
  }

  return gss_send(gss, sockfd, (void *)buf, len);
}

ssize_t
sendto(int sockfd, const void *buf, size_t len, int flags,
       const struct sockaddr *dest_addr, socklen_t addrlen)
{
  gss_auto_t *gss = idx_get(&idx, sockfd);
  if (!gss)
    return NEXT(sendto)(sockfd, buf, len, flags, dest_addr, addrlen);

  if (flags || dest_addr) {
    errno = ENOSYS; /* TODO */
    return -1;
  }

  return gss_send(gss, sockfd, (void *)buf, len);
}

ssize_t
sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
  gss_auto_t *gss = idx_get(&idx, sockfd);
  if (!gss)
    return NEXT(sendmsg)(sockfd, msg, flags);

  errno = ENOSYS; /* TODO */
  return -1;
}

int
setsockopt(int sockfd, int level, int optname, const void *optval,
           socklen_t optlen)
{
  gss_auto_t *gss = NULL;

  if (level != IPPROTO_GSS)
    return NEXT(setsockopt)(sockfd, level, optname, optval, optlen);

  gss = idx_get(&idx, sockfd);
  if (!gss) /* uhhh... */
    return NEXT(setsockopt)(sockfd, level, optname, optval, optlen);

  return gss_setsockopt(gss, sockfd, optname, optval, optlen);
}

int
socket(int domain, int type, int protocol)
{
  gss_auto_t *gss = NULL;
  int fd = -1;

  /* non-TCP operation has too many failure modes to consider supporting
   * without having a serious use case first. */
  if (protocol == IPPROTO_GSS && type != SOCK_STREAM) {
    errno = ENOTSUP;
    return -1;
  }

  fd = NEXT(socket)(domain, type, (protocol == IPPROTO_GSS) ? 0 : protocol);
  if (fd < 0 || protocol != IPPROTO_GSS)
    return fd;

  gss = gss_new();
  if (!gss || !idx_set(&idx, fd, gss, NULL)) {
    close(fd);
    return -1;
  }

  return fd;
}

ssize_t
write(int fd, const void *buf, size_t count)
{
  gss_auto_t *gss = idx_get(&idx, fd);
  if (!gss)
    return NEXT(write)(fd, buf, count);

  return gss_send(gss, fd, (void *)buf, count);
}
