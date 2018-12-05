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

#define _GNU_SOURCE
#include "tlssock.h"

#include <gnutls/gnutls.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <poll.h>
#include <limits.h>

#define __str(s) #s
#define _str(s) __str(s)
#define NEXT(name) ((typeof(name) *) dlsym(RTLD_NEXT, _str(name)))

#define tls_auto_t tls_t __attribute__((cleanup(tls_rel)))

typedef enum {
  UNDEFINED = 0,
  CREATED,
  LISTENING,
  ACCEPTED,
  CONNECTED,
  ESTABLISHED,
  SHUTDOWN,
} state_t;

typedef enum {
  CRED_TYPE_ANON,
} cred_type_t;

typedef struct {
  gnutls_certificate_credentials_t cert;

  struct {
    gnutls_anon_client_credentials_t anon;
    gnutls_psk_client_credentials_t psk;
    gnutls_srp_client_credentials_t srp;
  } clt;

  struct {
    gnutls_anon_server_credentials_t anon;
    gnutls_psk_server_credentials_t psk;
    gnutls_srp_server_credentials_t srp;
  } srv;
} creds_t;

typedef struct {
  int flags;
} created_t;

typedef struct {
  int flags;
} listening_t;

typedef struct {
  int flags;
  creds_t creds;
} accepted_t;

typedef struct {
  int flags;
  creds_t creds;
} connected_t;

typedef struct {
  gnutls_session_t session;
  creds_t creds;
} established_t;

typedef struct {
  gnutls_session_t session;
  creds_t creds;
} shutdown_t;

typedef struct {
  state_t state;

  union {
    created_t created;
    listening_t listening;
    accepted_t accepted;
    connected_t connected;
    established_t established;
    shutdown_t shutdown;
  };
} tls_t;

typedef struct {
  pthread_mutex_t mutex;
  tls_t tls;
} ent_t;

static struct {
  pthread_rwlock_t rwl;
  ent_t **ent;
  size_t len;
} idx = { .rwl = PTHREAD_RWLOCK_INITIALIZER };

static inline int
err(int errnum)
{
  errno = errnum;
  return -1;
}

static inline int
gnutls2errno(int ret)
{
  switch (ret) {
  case GNUTLS_E_SUCCESS:      return 0;
  case GNUTLS_E_AGAIN:        return err(EAGAIN);
  case GNUTLS_E_INTERRUPTED:  return err(EINTR);
  case GNUTLS_E_LARGE_PACKET: return err(EMSGSIZE);
  default: return gnutls_error_is_fatal(ret) ? err(EIO) : 0; // FIXME
  }
}

static void
creds_clr(creds_t *creds)
{
  gnutls_certificate_free_credentials(creds->cert);
  gnutls_anon_free_client_credentials(creds->clt.anon);
  gnutls_psk_free_client_credentials(creds->clt.psk);
  gnutls_srp_free_client_credentials(creds->clt.srp);
  gnutls_anon_free_server_credentials(creds->srv.anon);
  gnutls_psk_free_server_credentials(creds->srv.psk);
  gnutls_srp_free_server_credentials(creds->srv.srp);

  memset(creds, 0, sizeof(*creds));
}

static void
tls_rel(tls_t **tls)
{
  ent_t *ent = NULL;

  if (!tls || !*tls)
    return;

  ent = (ent_t *) (((uint8_t *) *tls) - offsetof(ent_t, tls));
  pthread_mutex_unlock(&ent->mutex);
  pthread_rwlock_unlock(&idx.rwl);
}

static void
tls_clr(tls_t *tls)
{
  switch (tls->state) {
  case UNDEFINED:
  case LISTENING:
  case CREATED:
    break;

  case CONNECTED:
    creds_clr(&tls->connected.creds);
    break;

  case ACCEPTED:
    creds_clr(&tls->accepted.creds);
    break;

  case ESTABLISHED:
    gnutls_deinit(tls->established.session);
    creds_clr(&tls->established.creds);
    break;

  case SHUTDOWN:
    gnutls_deinit(tls->shutdown.session);
    creds_clr(&tls->shutdown.creds);
    break;
  }

  memset(tls, 0, sizeof(*tls));
}

static tls_t *
tls_new(int fd)
{
  static const size_t BLOCK = 128;

  if (fd < 0) {
    errno = EBADF;
    return NULL;
  }

  pthread_rwlock_wrlock(&idx.rwl);

  if (idx.len <= (unsigned int) fd) {
    ent_t **ent = NULL;
    size_t len = 0;

    len = (fd + BLOCK) / BLOCK * BLOCK;
    ent = realloc(idx.ent, sizeof(ent_t*) * len);
    if (!ent) {
      pthread_rwlock_unlock(&idx.rwl);
      return NULL;
    }

    memset(&ent[idx.len], 0, sizeof(ent_t*) * (len - idx.len));
    idx.len = len;
    idx.ent = ent;
  }

  if (idx.ent[fd]) {
    tls_clr(&idx.ent[fd]->tls);
  } else {
    int r;

    idx.ent[fd] = calloc(1, sizeof(ent_t));
    if (!idx.ent[fd]) {
      pthread_rwlock_unlock(&idx.rwl);
      return NULL;
    }

    r = pthread_mutex_init(&idx.ent[fd]->mutex, NULL);
    if (r != 0) {
      pthread_rwlock_unlock(&idx.rwl);
      errno = r;
      return NULL;
    }
  }

  pthread_mutex_lock(&idx.ent[fd]->mutex);
  return &idx.ent[fd]->tls;
}

static tls_t *
tls_get(int fd, int (*lock)(pthread_rwlock_t *rwlock))
{
  if (fd < 0) {
    errno = EBADF;
    return NULL;
  }

  if (lock)
    lock(&idx.rwl);

  if (idx.len <= (unsigned int) fd) {
    if (lock)
      pthread_rwlock_unlock(&idx.rwl);
    errno = ENOTSOCK;
    fcntl(fd, F_GETFD); // Possibly replace ENOTSOCK with EBADF
    return NULL;
  }

  if (!idx.ent[fd]) {
    if (lock)
      pthread_rwlock_unlock(&idx.rwl);
    errno = ENOTSOCK;
    return NULL;
  }

  pthread_mutex_lock(&idx.ent[fd]->mutex);
  return &idx.ent[fd]->tls;
}

static bool
tls_del(int fd, bool lock)
{
  tls_t *tls;

  tls = tls_get(fd, lock ? pthread_rwlock_wrlock : NULL);
  if (!tls)
    return false;

  tls_clr(tls);
  pthread_mutex_unlock(&idx.ent[fd]->mutex);
  pthread_mutex_destroy(&idx.ent[fd]->mutex);

  free(idx.ent[fd]);
  idx.ent[fd] = NULL;
  if (lock)
    pthread_rwlock_unlock(&idx.rwl);

  return true;
}

static ssize_t
tls_read(tls_t *tls, void *buf, size_t count)
{
  ssize_t ret = 0;

  switch (tls->state) {
  case ESTABLISHED:
    break;

  case UNDEFINED:
  case CREATED:
  case LISTENING:
  case ACCEPTED:
  case CONNECTED:
  case SHUTDOWN:
    return err(EBADFD); // FIXME
  }

  ret = gnutls_record_recv(tls->established.session, buf, count);
  if (ret >= 0)
    return ret;

  return gnutls_error_is_fatal(ret) ? gnutls2errno(ret) : -1;
}

static ssize_t
tls_write(tls_t *tls, const void *buf, size_t count)
{
  int ret;

  switch (tls->state) {
  case ESTABLISHED:
    break;

  case UNDEFINED:
  case CREATED:
  case LISTENING:
  case ACCEPTED:
  case CONNECTED:
  case SHUTDOWN:
    return err(EBADFD); // FIXME
  }

  ret = gnutls_record_send(tls->established.session, buf, count);
  if (ret >= 0)
    return ret;

  return gnutls_error_is_fatal(ret) ? gnutls2errno(ret) : -1;
}

static inline int
notsup(int fd)
{
  tls_auto_t *tls = NULL;

  tls = tls_get(fd, pthread_rwlock_rdlock);
  if (tls)
    return err(ENOTSUP);

  if (errno == ENOTSOCK)
    return 0;

  return -1;
}

int
accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
  return accept4(sockfd, addr, addrlen, 0);
}

int
accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
  tls_auto_t *tls = NULL;
  tls_auto_t *con = NULL;
  int fd;

  tls = tls_get(sockfd, pthread_rwlock_rdlock);
  if (!tls)
    return -1;

  switch (tls->state) {
  case UNDEFINED:   break;
  case CREATED:     return err(EBADFD); // FIXME
  case LISTENING:   break;
  case ACCEPTED:    return err(EBADFD); // FIXME
  case SHUTDOWN:    return err(EBADFD); // FIXME
  case CONNECTED:   return err(EBADFD); // FIXME
  case ESTABLISHED: return err(EBADFD); // FIXME
  }

  fd = NEXT(accept4)(sockfd, addr, addrlen, flags);
  if (fd < 0)
    return fd;

  con = tls_new(fd);
  if (!con) {
    close(fd);
    return -1;
  }

  if (tls->state == LISTENING) {
    con->accepted.flags = tls->listening.flags;
    con->state = ACCEPTED;
  }

  return fd;
}

int
close(int fd)
{
  tls_del(fd, true);
  return NEXT(close)(fd);
}

int
connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
  tls_auto_t *tls = NULL;
  int ret;

  tls = tls_get(sockfd, pthread_rwlock_rdlock);
  if (!tls)
    return -1;

  switch (tls->state) {
  case UNDEFINED:   return NEXT(connect)(sockfd, addr, addrlen);
  case CREATED:     break;
  case LISTENING:   return err(EBADFD); // FIXME
  case ACCEPTED:    return err(EBADFD); // FIXME
  case SHUTDOWN:    return err(EBADFD); // FIXME
  case CONNECTED:   return err(EBADFD); // FIXME
  case ESTABLISHED: return err(EBADFD); // FIXME
  }

  ret = NEXT(connect)(sockfd, addr, addrlen);

  if (ret == 0) {
    tls->connected.flags = tls->created.flags | GNUTLS_CLIENT;
    tls->state = CONNECTED;
  }

  return ret;
}

int
dup(int oldfd)
{
  return notsup(oldfd) != 0 ? -1 :
    NEXT(dup)(oldfd);
}

int
dup2(int oldfd, int newfd)
{
  return notsup(oldfd) != 0 ? -1 :
    NEXT(dup2)(oldfd, newfd);
}

FILE *
fdopen(int fd, const char *mode)
{
  return notsup(fd) != 0 ? NULL :
    NEXT(fdopen)(fd, mode);
}

int
getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen)
{
  // TODO
  return NEXT(getsockopt)(sockfd, level, optname, optval, optlen);
}

int
listen(int sockfd, int backlog)
{
  tls_auto_t *tls = NULL;
  int ret;

  tls = tls_get(sockfd, pthread_rwlock_rdlock);
  if (!tls)
    return -1;

  switch (tls->state) {
  case UNDEFINED:   return NEXT(listen)(sockfd, backlog);
  case CREATED:     break;
  case LISTENING:   return err(EBADFD); // FIXME
  case ACCEPTED:    return err(EBADFD); // FIXME
  case SHUTDOWN:    return err(EBADFD); // FIXME
  case CONNECTED:   return err(EBADFD); // FIXME
  case ESTABLISHED: return err(EBADFD); // FIXME
  }

  ret = NEXT(listen)(sockfd, backlog);

  if (ret == 0) {
    tls->listening.flags = tls->created.flags | GNUTLS_SERVER;
    tls->state = LISTENING;
  }

  return ret;
}

ssize_t
pread(int fd, void *buf, size_t count, off_t offset)
{
  tls_auto_t *tls = NULL;

  tls = tls_get(fd, pthread_rwlock_rdlock);
  if (!tls)
    return -1;

  if (tls->state == UNDEFINED)
    return NEXT(pread)(fd, buf, count, offset);

  return err(ENOSYS); // TODO
}

ssize_t
preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
  tls_auto_t *tls = NULL;

  tls = tls_get(fd, pthread_rwlock_rdlock);
  if (!tls)
    return -1;

  if (tls->state == UNDEFINED)
    return NEXT(preadv)(fd, iov, iovcnt, offset);

  return err(ENOSYS); // TODO
}

ssize_t
preadv2(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags)
{
  tls_auto_t *tls = NULL;

  tls = tls_get(fd, pthread_rwlock_rdlock);
  if (!tls)
    return -1;

  if (tls->state == UNDEFINED)
    return NEXT(preadv2)(fd, iov, iovcnt, offset, flags);

  return err(ENOSYS); // TODO
}

ssize_t
pwrite(int fd, const void *buf, size_t count, off_t offset)
{
  tls_auto_t *tls = NULL;

  tls = tls_get(fd, pthread_rwlock_rdlock);
  if (!tls)
    return -1;

  if (tls->state == UNDEFINED)
    return NEXT(pwrite)(fd, buf, count, offset);

  return err(ENOSYS); // TODO
}

ssize_t
pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
  tls_auto_t *tls = NULL;

  tls = tls_get(fd, pthread_rwlock_rdlock);
  if (!tls)
    return -1;

  if (tls->state == UNDEFINED)
    return NEXT(pwritev)(fd, iov, iovcnt, offset);

  return err(ENOSYS); // TODO
}

ssize_t
pwritev2(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags)
{
  tls_auto_t *tls = NULL;

  tls = tls_get(fd, pthread_rwlock_rdlock);
  if (!tls)
    return -1;

  if (tls->state == UNDEFINED)
    return NEXT(pwritev2)(fd, iov, iovcnt, offset, flags);

  return err(ENOSYS); // TODO
}

ssize_t
read(int fd, void *buf, size_t count)
{
  tls_auto_t *tls = NULL;

  tls = tls_get(fd, pthread_rwlock_rdlock);
  if (!tls)
    return -1;

  if (tls->state == UNDEFINED)
    return NEXT(read)(fd, buf, count);

  return tls_read(tls, buf, count);
}

ssize_t
recv(int sockfd, void *buf, size_t len, int flags)
{
  tls_auto_t *tls = NULL;

  tls = tls_get(sockfd, pthread_rwlock_rdlock);
  if (!tls)
    return -1;

  if (tls->state == UNDEFINED)
    return NEXT(read)(sockfd, buf, len);

  return tls_read(tls, buf, len);
}

ssize_t
recvfrom(int sockfd, void *buf, size_t len, int flags,
         struct sockaddr *src_addr, socklen_t *addrlen)
{
  if (src_addr == NULL && addrlen == NULL)
    return recv(sockfd, buf, len, flags);

  return notsup(sockfd) != 0 ? -1 :
    NEXT(recvfrom)(sockfd, buf, len, flags, src_addr, addrlen);
}

ssize_t
recvmsg(int sockfd, struct msghdr *msg, int flags)
{
  return notsup(sockfd) != 0 ? -1 :
    NEXT(recvmsg)(sockfd, msg, flags);
}

ssize_t
send(int sockfd, const void *buf, size_t len, int flags)
{
  tls_auto_t *tls = NULL;

  tls = tls_get(sockfd, pthread_rwlock_rdlock);
  if (!tls)
    return -1;

  if (tls->state == UNDEFINED)
    return NEXT(send)(sockfd, buf, len, flags);

  return tls_write(tls, buf, len);
}

ssize_t
sendto(int sockfd, const void *buf, size_t len, int flags,
       const struct sockaddr *dest_addr, socklen_t addrlen)
{
  if (dest_addr == NULL && addrlen == 0)
    return send(sockfd, buf, len, flags);

  return notsup(sockfd) != 0 ? -1 :
    NEXT(sendto)(sockfd, buf, len, flags, dest_addr, addrlen);
}

ssize_t
sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
  return notsup(sockfd) != 0 ? -1 :
    NEXT(sendmsg)(sockfd, msg, flags);
}

static ssize_t
pull_func(gnutls_transport_ptr_t ptr, void *buf, size_t count)
{
  int fd = (uintptr_t) ptr;
  return NEXT(read)(fd, buf, count);
}

static ssize_t
push_func(gnutls_transport_ptr_t ptr, const void *buf, size_t count)
{
  int fd = (uintptr_t) ptr;
  return NEXT(write)(fd, buf, count);
}

static ssize_t
vec_push_func(gnutls_transport_ptr_t ptr, const giovec_t *iov, int iovcnt)
{
  int fd = (uintptr_t) ptr;
  return NEXT(writev)(fd, iov, iovcnt);
}

static int
pull_timeout_func(gnutls_transport_ptr_t ptr, unsigned int ms)
{
  struct pollfd fd = { (uintptr_t) ptr, POLLIN | POLLPRI };
  int timeout = 0;

  if (ms == GNUTLS_INDEFINITE_TIMEOUT)
    timeout = -1;
  else if (ms > INT_MAX)
    timeout = INT_MAX;
  else
    timeout = ms;

  return poll(&fd, 1, timeout);
}

int
setsockopt(int sockfd, int level, int optname,
           const void *optval, socklen_t optlen)
{
  tls_opt_t opt = optname;
  tls_auto_t *tls = NULL;
  creds_t *creds;
  bool client;
  int ret;

  if (level != PROT_TLS)
    return NEXT(setsockopt)(sockfd, level, optname, optval, optlen);

  tls = tls_get(sockfd, pthread_rwlock_rdlock);
  if (!tls)
    return -1;

  switch (tls->state) {
  case CONNECTED:   client = true;  creds = &tls->connected.creds; break;
  case ACCEPTED:    client = false; creds = &tls->accepted.creds;  break;
  case CREATED:     return err(EBADFD); // FIXME
  case SHUTDOWN:    return err(EBADFD); // FIXME
  case LISTENING:   return err(EBADFD); // FIXME
  case UNDEFINED:   return err(EBADFD); // FIXME
  case ESTABLISHED: return err(EBADFD); // FIXME
  }

  switch (opt) {
  case TLS_OPT_PEER_NAME:
    return err(ENOSYS); // TODO

  case TLS_OPT_PEER_CERT:
    if (!creds->cert) {
      ret = gnutls2errno(gnutls_certificate_allocate_credentials(&creds->cert));
      if (ret != 0)
        return ret;
    }

    return err(ENOSYS); // TODO

  case TLS_OPT_SELF_CERT:
    if (!creds->cert) {
      ret = gnutls2errno(gnutls_certificate_allocate_credentials(&creds->cert));
      if (ret != 0)
        return ret;
    }

    return err(ENOSYS); // TODO

  case TLS_OPT_SELF_ANON:
    if (client) {
      if (creds->clt.anon)
        return 0;

      ret = gnutls_anon_allocate_client_credentials(&creds->clt.anon);
    } else {
      if (creds->srv.anon)
        return 0;

      ret = gnutls_anon_allocate_server_credentials(&creds->srv.anon);
    }

    return gnutls2errno(ret);

  case TLS_OPT_HANDSHAKE: {
    int flags = client ? tls->connected.flags : tls->accepted.flags;
    unsigned int ms = GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT;
    gnutls_session_t session = NULL;
    const unsigned int *v = optval;

    if (v) {
      if (optlen != sizeof(*v))
        return err(EINVAL);

      ms = *v;
    }

    ret = gnutls_init(&session, flags);

    if (ret == GNUTLS_E_SUCCESS) {
      uintptr_t fd = sockfd;

      gnutls_transport_set_ptr(session, (gnutls_transport_ptr_t) fd);
      gnutls_transport_set_pull_function(session, pull_func);
      gnutls_transport_set_push_function(session, push_func);
      gnutls_transport_set_vec_push_function(session, vec_push_func);
      gnutls_transport_set_pull_timeout_function(session, pull_timeout_func);
      gnutls_handshake_set_timeout(session, ms);
    }

    if (ret == GNUTLS_E_SUCCESS && creds->cert)
      ret = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, creds->cert);

    if (client) {
      if (ret == GNUTLS_E_SUCCESS && creds->clt.anon)
        ret = gnutls_credentials_set(session, GNUTLS_CRD_ANON, creds->clt.anon);

      if (ret == GNUTLS_E_SUCCESS && creds->clt.psk)
        ret = gnutls_credentials_set(session, GNUTLS_CRD_PSK, creds->clt.psk);

      if (ret == GNUTLS_E_SUCCESS && creds->clt.srp)
        ret = gnutls_credentials_set(session, GNUTLS_CRD_SRP, creds->clt.srp);
    } else {
      if (ret == GNUTLS_E_SUCCESS && creds->srv.anon)
        ret = gnutls_credentials_set(session, GNUTLS_CRD_ANON, creds->srv.anon);

      if (ret == GNUTLS_E_SUCCESS && creds->srv.psk)
        ret = gnutls_credentials_set(session, GNUTLS_CRD_PSK, creds->srv.psk);

      if (ret == GNUTLS_E_SUCCESS && creds->srv.srp)
        ret = gnutls_credentials_set(session, GNUTLS_CRD_SRP, creds->srv.srp);
    }

    if (ret == GNUTLS_E_SUCCESS)
      ret = gnutls_handshake(session);

    if (gnutls2errno(ret) != 0)
      return -1;

    tls->established.creds = *creds;
    tls->established.session = session;
    tls->state = ESTABLISHED;

    return 0;
  }

  default:
    return err(EINVAL); // FIXME
  }

  abort();
}

int
shutdown(int sockfd, int how)
{
  gnutls_close_request_t ghow;
  tls_auto_t *tls = NULL;
  int ret = 0;

  tls = tls_get(sockfd, pthread_rwlock_rdlock);
  if (!tls)
    return -1;

  switch (tls->state) {
  case UNDEFINED:
  case SHUTDOWN:
    return NEXT(shutdown)(sockfd, how);

  case LISTENING:
  case CONNECTED:
  case ACCEPTED:
  case CREATED:
    tls_clr(tls);
    tls->state = SHUTDOWN;
    return NEXT(shutdown)(sockfd, how);

  case ESTABLISHED:
    break;
  }

  switch (how) {
  case SHUT_RD:   return err(ENOTSUP);
  case SHUT_WR:   ghow = GNUTLS_SHUT_WR; break;
  case SHUT_RDWR: ghow = GNUTLS_SHUT_RDWR; break;
  default:        return err(EINVAL);
  }

  ret = gnutls2errno(gnutls_bye(tls->established.session, ghow));

  if (ret == 0) {
    tls->shutdown.session = tls->established.session;
    tls->shutdown.creds = tls->established.creds;
    tls->state = SHUTDOWN;
  }

  return ret;
}

int
socket(int domain, int type, int protocol)
{
  tls_auto_t *tls = NULL;
  int flags = 0;
  int fd = -1;

  if (protocol == PROT_TLS) {
    int noflags = type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC);

    if (domain != AF_INET6 && domain != AF_INET)
      return err(EPROTONOSUPPORT);

    if (type & SOCK_NONBLOCK)
      flags |= GNUTLS_NONBLOCK;

    if (noflags == SOCK_DGRAM)
      flags |= GNUTLS_DATAGRAM;
    else if (noflags != SOCK_STREAM)
      return err(EPROTONOSUPPORT);
  }

  fd = NEXT(socket)(domain, type, protocol == PROT_TLS ? 0 : protocol);
  if (fd < 0)
    return fd;

  tls = tls_new(fd);
  if (!tls) {
    close(fd);
    return -1;
  }

  if (protocol == PROT_TLS) {
    tls->created.flags = flags;
    tls->state = CREATED;
  }

  return fd;
}

ssize_t
write(int fd, const void *buf, size_t count)
{
  tls_auto_t *tls = NULL;

  tls = tls_get(fd, pthread_rwlock_rdlock);
  if (!tls)
    return -1;

  if (tls->state == UNDEFINED)
    return NEXT(write)(fd, buf, count);

  return tls_write(tls, buf, count);
}

static void __attribute__((destructor))
destructor(void)
{
  pthread_rwlock_rdlock(&idx.rwl);

  for (size_t i = 0; i < idx.len; i++)
    tls_del(i, false);

  free(idx.ent);
  idx.ent = NULL;
  idx.len = 0;

  pthread_rwlock_destroy(&idx.rwl);
}
