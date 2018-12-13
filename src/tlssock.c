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

#include "core.h"
#include "tlssock.h"
#include "idx.h"

#include <sys/uio.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>

static inline bool
is_tls(int fd, int errnum)
{
  tls_auto_t *tls = NULL;
  tls = idx_get(fd);
  if (tls && errnum != 0)
    errno = errnum;
  return tls;
}

static int
inner_protocol(int protocol)
{
  switch (protocol) {
  case IPPROTO_TLS_CLT: return 0;
  case IPPROTO_TLS_SRV: return 0;
  default: return protocol;
  }
}

int
accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
  return accept4(sockfd, addr, addrlen, 0);
}

int
accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
  int fd;

  fd = NEXT(accept4)(sockfd, addr, addrlen, flags);

  if (fd >= 0) {
    tls_auto_t *lis = NULL;

    lis = idx_get(sockfd);
    if (lis) {
      tls_auto_t *con = NULL;

      con = tls_new(fd, tls_is_client(lis));
      if (!con || !idx_set(fd, con, NULL)) {
        close(fd);
        return -1;
      }
    }
  }

  return fd;
}

int
close(int fd)
{
  idx_del(fd);
  return NEXT(close)(fd);
}

int
dup(int oldfd)
{
  return is_tls(oldfd, ENOTSUP) ? -1 :
    NEXT(dup)(oldfd);
}

int
dup2(int oldfd, int newfd)
{
  return is_tls(oldfd, ENOTSUP) ? -1 :
    NEXT(dup2)(oldfd, newfd);
}

FILE *
fdopen(int fd, const char *mode)
{
  return is_tls(fd, ENOTSUP) ? NULL :
    NEXT(fdopen)(fd, mode);
}

int
getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen)
{
  int *prot = optval;
  int ret;

  /* Pass TLS level options into the tls_t layer. */
  if (level == IPPROTO_TLS_CLT || level == IPPROTO_TLS_SRV) {
    tls_auto_t *tls = NULL;
    tls = idx_get(sockfd);
    if (!tls || tls_is_client(tls) != (level == IPPROTO_TLS_CLT)) {
      errno = EINVAL; // FIXME
      return -1;
    }

    return tls_getsockopt(tls, optname, optval, optlen);
  }

  ret = NEXT(getsockopt)(sockfd, level, optname, optval, optlen);

  /* Translate the inner protocol to the outer one. */
  if (ret >= 0 && level == SOL_SOCKET && optname == SO_PROTOCOL && is_tls_inner_protocol(*prot)) {
    tls_auto_t *tls = NULL;

    if (*optlen != sizeof(*prot)) {
      errno = EINVAL; // FIXME
      return -1;
    }

    tls = idx_get(sockfd);
    if (tls)
      *prot = tls_is_client(tls) ? IPPROTO_TLS_CLT : IPPROTO_TLS_SRV;
  }

  return ret;
}

ssize_t
pread(int fd, void *buf, size_t count, off_t offset)
{
  return is_tls(fd, ENOSYS) ? -1 : // TODO
    NEXT(pread)(fd, buf, count, offset);
}

ssize_t
preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
  return is_tls(fd, ENOSYS) ? -1 : // TODO
    NEXT(preadv)(fd, iov, iovcnt, offset);
}

ssize_t
preadv2(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags)
{
  return is_tls(fd, ENOSYS) ? -1 : // TODO
    NEXT(preadv2)(fd, iov, iovcnt, offset, flags);
}

ssize_t
pwrite(int fd, const void *buf, size_t count, off_t offset)
{
  return is_tls(fd, ENOSYS) ? -1 : // TODO
    NEXT(pwrite)(fd, buf, count, offset);
}

ssize_t
pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
  return is_tls(fd, ENOSYS) ? -1 : // TODO
    NEXT(pwritev)(fd, iov, iovcnt, offset);
}

ssize_t
pwritev2(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags)
{
  return is_tls(fd, ENOSYS) ? -1 : // TODO
    NEXT(pwritev2)(fd, iov, iovcnt, offset, flags);
}

ssize_t
read(int fd, void *buf, size_t count)
{
  tls_auto_t *tls = NULL;

  tls = idx_get(fd);
  if (!tls)
    return NEXT(read)(fd, buf, count);

  return tls_read(tls, buf, count);
}

ssize_t
recv(int sockfd, void *buf, size_t len, int flags)
{
  tls_auto_t *tls = NULL;

  tls = idx_get(sockfd);
  if (!tls)
    return NEXT(recv)(sockfd, buf, len, flags);

  if (flags != 0)
    return EINVAL; // FIXME

  return tls_read(tls, buf, len);
}

ssize_t
recvfrom(int sockfd, void *buf, size_t len, int flags,
         struct sockaddr *src_addr, socklen_t *addrlen)
{
  if (src_addr == NULL && addrlen == NULL)
    return recv(sockfd, buf, len, flags);

  return is_tls(sockfd, ENOSYS) ? -1 : // TODO
    NEXT(recvfrom)(sockfd, buf, len, flags, src_addr, addrlen);
}

ssize_t
recvmsg(int sockfd, struct msghdr *msg, int flags)
{
  return is_tls(sockfd, ENOSYS) ? -1 : // TODO
    NEXT(recvmsg)(sockfd, msg, flags);
}

ssize_t
send(int sockfd, const void *buf, size_t len, int flags)
{
  tls_auto_t *tls = NULL;

  tls = idx_get(sockfd);
  if (!tls)
    return NEXT(send)(sockfd, buf, len, flags);

  if (flags != 0)
    return EINVAL; // FIXME

  return tls_write(tls, buf, len);
}

ssize_t
sendto(int sockfd, const void *buf, size_t len, int flags,
       const struct sockaddr *dest_addr, socklen_t addrlen)
{
  if (dest_addr == NULL && addrlen == 0)
    return send(sockfd, buf, len, flags);

  return is_tls(sockfd, ENOSYS) ? -1 : // TODO
    NEXT(sendto)(sockfd, buf, len, flags, dest_addr, addrlen);
}

ssize_t
sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
  return is_tls(sockfd, ENOSYS) ? -1 : // TODO
    NEXT(sendmsg)(sockfd, msg, flags);
}

int
setsockopt(int sockfd, int level, int optname,
           const void *optval, socklen_t optlen)
{
  tls_auto_t *already = NULL;
  tls_auto_t *tls = NULL;

  /* Pass TLS level options into the tls_t layer. */
  if (level == IPPROTO_TLS_CLT || level == IPPROTO_TLS_SRV) {
    tls = idx_get(sockfd);
    if (!tls || tls_is_client(tls) != (level == IPPROTO_TLS_CLT)) {
      errno = EINVAL; // FIXME
      return -1;
    }

    return tls_setsockopt(tls, optname, optval, optlen);
  }

  /* We only override SO_PROTOCOL on SOL_SOCKET. */
  if (level != SOL_SOCKET || optname != SO_PROTOCOL)
    return NEXT(setsockopt)(sockfd, level, optname, optval, optlen);

  /* Confirm the correct size of the input. */
  if (optlen != sizeof(int)) {
    errno = EINVAL; // FIXME
    return -1;
  }

  const int *const protocol = optval;
  const bool client = *protocol == IPPROTO_TLS_CLT;

  /* The caller wants to transition to TLS. */
  if (is_tls_protocol(*protocol)) {
    /* Create the new TLS instance. */
    tls = tls_new(sockfd, client);
    if (!tls)
      return -1;

    /* If setting the TLS instance worked, we're now TLS. */
    if (idx_set(sockfd, tls, &already))
      return 0;

    /* Otherwise, set a context specific error. */
    if (already)
      errno = tls_is_client(already) == client ? EALREADY : EINVAL; // FIXME

    return -1;

  /* The caller wants to transition to non-TLS. */
  } else {
    /* If deletion succeeded, then transition was successful. */
    if (idx_del(sockfd))
      return 0;

    /* If the error is that there was no entry,
     * then indicated that we are already non-TLS. */
    if (errno == ENOENT)
      errno = EALREADY; // FIXME

    return -1;
  }
}

int
socket(int domain, int type, int protocol)
{
  tls_auto_t *tls = NULL;
  int fd = -1;

  fd = NEXT(socket)(domain, type, inner_protocol(protocol));
  if (fd < 0)
    return fd;

  switch (protocol) {
  case IPPROTO_TLS_SRV:
  case IPPROTO_TLS_CLT:
    tls = tls_new(fd, protocol == IPPROTO_TLS_CLT);
    if (!tls || !idx_set(fd, tls, NULL)) {
      close(fd);
      return -1;
    }
  }

  return fd;
}

ssize_t
write(int fd, const void *buf, size_t count)
{
  tls_auto_t *tls = NULL;

  tls = idx_get(fd);
  if (!tls)
    return NEXT(write)(fd, buf, count);

  return tls_write(tls, buf, count);
}
