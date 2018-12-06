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
#include "tls.h"
#include "tlssock.h"

#include <gnutls/gnutls.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <limits.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>

#define lock_auto_t lock_t __attribute__((cleanup(lock_cleanup)))

typedef struct {
  pthread_rwlock_t lock;
} lock_t;

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

struct tls {
  lock_t lock;
  size_t ref;

  gnutls_session_t session;
  creds_t creds;
  int flags;
  int fd;
};

static int
getsockopt_int(int fd, int level, int optname, int *optval)
{
  socklen_t len = sizeof(*optval);
  int ret;

  ret = NEXT(getsockopt)(fd, level, optname, optval, &len);

  if (ret == 0 && len != sizeof(*optval)) {
    errno = EINVAL; // FIXME
    return -1;
  }

  return ret;
}

static inline int
gnutls2errno(int ret)
{
  switch (ret) {
  case GNUTLS_E_SUCCESS:      return 0;
  case GNUTLS_E_AGAIN:        errno = EAGAIN;   break;
  case GNUTLS_E_INTERRUPTED:  errno = EINTR;    break;
  case GNUTLS_E_LARGE_PACKET: errno = EMSGSIZE; break;
  default:
    if (!gnutls_error_is_fatal(ret))
      return 0;

    errno = EIO; // FIXME
    break;
  }

  return -1;
}

static void
creds_reset(creds_t *creds)
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
lock_cleanup(lock_t **lock)
{
  if (lock) {
    pthread_rwlock_unlock(&(*lock)->lock);
    *lock = NULL;
  }
}

static lock_t *
rdlock(tls_t *tls)
{
  if (!tls)
    return NULL;

  errno = pthread_rwlock_rdlock(&tls->lock.lock);
  if (errno != 0)
    return NULL;

  return &tls->lock;
}

static lock_t *
wrlock(tls_t *tls)
{
  if (!tls)
    return NULL;

  errno = pthread_rwlock_wrlock(&tls->lock.lock);
  if (errno != 0)
    return NULL;

  return &tls->lock;
}

tls_t *
tls_new(int fd, bool client)
{
  tls_t *tls = NULL;
  int protocol;
  int domain;
  int type;

  if (getsockopt_int(fd, SOL_SOCKET, SO_DOMAIN, &domain) < 0)
    return NULL;

  if (getsockopt_int(fd, SOL_SOCKET, SO_TYPE, &type) < 0)
    return NULL;

  if (getsockopt_int(fd, SOL_SOCKET, SO_PROTOCOL, &protocol) < 0)
    return NULL;

  if (domain != AF_INET && domain != AF_INET6) {
    errno = EINVAL; // FIXME
    return NULL;
  }

  if (protocol != 0) {
    errno = EINVAL; // FIXME
    return NULL;
  }

  if (type != SOCK_STREAM && type != SOCK_DGRAM) {
    errno = EINVAL; // FIXME
    return NULL;
  }

  tls = calloc(1, sizeof(*tls));
  if (!tls)
    return NULL;

  errno = pthread_rwlock_init(&tls->lock.lock, NULL);
  if (errno != 0) {
    free(tls);
    return NULL;
  }

  if (type == SOCK_DGRAM)
    tls->flags |= GNUTLS_DATAGRAM;

  tls->flags |= client ? GNUTLS_CLIENT : GNUTLS_SERVER;
  tls->ref = 1;
  tls->fd = fd;
  return tls;
}

void
tls_cleanup(tls_t **tls)
{
  if (tls)
    tls_decref(*tls);
}

tls_t *
tls_incref(tls_t *tls)
{
  {
    lock_auto_t *lock = wrlock(tls);

    if (!lock)
      return NULL;

    tls->ref++;
  }

  return tls;
}

tls_t *
tls_decref(tls_t *tls)
{
  {
    lock_auto_t *lock = wrlock(tls);

    if (!lock)
      return NULL;

    if (tls->ref-- > 1)
      return tls;

    gnutls_deinit(tls->session);
    creds_reset(&tls->creds);
  }

  pthread_rwlock_destroy(&tls->lock.lock);
  memset(tls, 0, sizeof(*tls));
  return NULL;
}

bool
tls_is_client(tls_t *tls)
{
  lock_auto_t *lock = rdlock(tls);
  return tls->flags & GNUTLS_CLIENT;
}

ssize_t
tls_read(tls_t *tls, void *buf, size_t count)
{
  lock_auto_t *lock = rdlock(tls);
  ssize_t ret = 0;

  ret = gnutls_record_recv(tls->session, buf, count);
  if (ret >= 0)
    return ret;

  return gnutls_error_is_fatal(ret) ? gnutls2errno(ret) : -1;
}

ssize_t
tls_write(tls_t *tls, const void *buf, size_t count)
{
  lock_auto_t *lock = rdlock(tls);
  int ret;

  ret = gnutls_record_send(tls->session, buf, count);
  if (ret >= 0)
    return ret;

  return gnutls_error_is_fatal(ret) ? gnutls2errno(ret) : -1;
}

int
tls_getsockopt(tls_t *tls, int optname, void *optval, socklen_t *optlen)
{
  lock_auto_t *lock = rdlock(tls);
  errno = ENOSYS; // TODO
  return -1;
}

static ssize_t
pull_func(gnutls_transport_ptr_t ptr, void *buf, size_t count)
{
  int *fd = ptr;
  return NEXT(read)(*fd, buf, count);
}

static ssize_t
push_func(gnutls_transport_ptr_t ptr, const void *buf, size_t count)
{
  int *fd = ptr;
  return NEXT(write)(*fd, buf, count);
}

static ssize_t
vec_push_func(gnutls_transport_ptr_t ptr, const giovec_t *iov, int iovcnt)
{
  int *fd = ptr;
  return NEXT(writev)(*fd, iov, iovcnt);
}

static int
pull_timeout_func(gnutls_transport_ptr_t ptr, unsigned int ms)
{
  int *fd = ptr;
  struct pollfd pfd = { *fd, POLLIN | POLLPRI };
  int timeout = 0;

  if (ms == GNUTLS_INDEFINITE_TIMEOUT)
    timeout = -1;
  else if (ms > INT_MAX)
    timeout = INT_MAX;
  else
    timeout = ms;

  return poll(&pfd, 1, timeout);
}

static int
handshake(tls_t *tls, const void *optval, socklen_t optlen)
{
  unsigned int ms = GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT;
  const unsigned int *const milliseconds = optval;
  gnutls_session_t session = NULL;
  int ret;

  if (milliseconds) {
    if (optlen != sizeof(*milliseconds)) {
      errno = EINVAL; // FIXME
      return -1;
    }

    ms = *milliseconds;
  }

  ret = fcntl(tls->fd, F_GETFL);
  if (ret < 0)
    return ret;

  ret = gnutls_init(&session,
                    tls->flags | (ret & O_NONBLOCK) ? GNUTLS_NONBLOCK : 0);
  if (ret == GNUTLS_E_SUCCESS) {
    gnutls_transport_set_ptr(session, &tls->fd);
    gnutls_transport_set_pull_function(session, pull_func);
    gnutls_transport_set_push_function(session, push_func);
    gnutls_transport_set_vec_push_function(session, vec_push_func);
    gnutls_transport_set_pull_timeout_function(session, pull_timeout_func);
    gnutls_handshake_set_timeout(session, ms);
    gnutls_set_default_priority(session);
  }

  if (ret == GNUTLS_E_SUCCESS && tls->creds.cert)
    ret = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, tls->creds.cert);

  if (tls->flags & GNUTLS_CLIENT) {
    if (ret == GNUTLS_E_SUCCESS && tls->creds.clt.anon)
      ret = gnutls_credentials_set(session, GNUTLS_CRD_ANON, tls->creds.clt.anon);

    if (ret == GNUTLS_E_SUCCESS && tls->creds.clt.psk)
      ret = gnutls_credentials_set(session, GNUTLS_CRD_PSK, tls->creds.clt.psk);

    if (ret == GNUTLS_E_SUCCESS && tls->creds.clt.srp)
      ret = gnutls_credentials_set(session, GNUTLS_CRD_SRP, tls->creds.clt.srp);
  } else {
    if (ret == GNUTLS_E_SUCCESS && tls->creds.srv.anon)
      ret = gnutls_credentials_set(session, GNUTLS_CRD_ANON, tls->creds.srv.anon);

    if (ret == GNUTLS_E_SUCCESS && tls->creds.srv.psk)
      ret = gnutls_credentials_set(session, GNUTLS_CRD_PSK, tls->creds.srv.psk);

    if (ret == GNUTLS_E_SUCCESS && tls->creds.srv.srp)
      ret = gnutls_credentials_set(session, GNUTLS_CRD_SRP, tls->creds.srv.srp);
  }

  if (ret == GNUTLS_E_SUCCESS)
    ret = gnutls_handshake(session);

  if (gnutls2errno(ret) != 0) {
    gnutls_free(session);
    return -1;
  }

  tls->session = session;
  return 0;
}

static int
self_anon(tls_t *tls, const void *optval, socklen_t optlen)
{
  const unsigned int *const enable = optval;
  int ret = GNUTLS_E_SUCCESS;

  if (!optval || optlen != sizeof(*enable)) {
    errno = EINVAL; // FIXME
    return -1;
  }

  if (tls->flags & GNUTLS_CLIENT) {
    if (*enable) {
      if (!tls->creds.clt.anon)
        ret = gnutls_anon_allocate_client_credentials(&tls->creds.clt.anon);
    } else {
      gnutls_anon_free_client_credentials(tls->creds.clt.anon);
      tls->creds.clt.anon = NULL;
    }

  } else {
    if (*enable) {
      if (!tls->creds.srv.anon)
        ret = gnutls_anon_allocate_server_credentials(&tls->creds.srv.anon);
    } else {
      gnutls_anon_free_server_credentials(tls->creds.srv.anon);
      tls->creds.srv.anon = NULL;
    }
  }

  return gnutls2errno(ret);
}

int
tls_setsockopt(tls_t *tls, int optname, const void *optval, socklen_t optlen)
{
  lock_auto_t *lock = wrlock(tls);

  switch (optname) {
  case TLS_OPT_HANDSHAKE: return handshake(tls, optval, optlen);
  case TLS_OPT_PEER_NAME: errno = ENOSYS; return -1; // TODO
  case TLS_OPT_PEER_CERT: errno = ENOSYS; return -1; // TODO
  case TLS_OPT_SELF_NAME: errno = ENOSYS; return -1; // TODO
  case TLS_OPT_SELF_CERT: errno = ENOSYS; return -1; // TODO
  case TLS_OPT_SELF_ANON: return self_anon(tls, optval, optlen);
  default: errno = ENOPROTOOPT; return -1; // FIXME
  }
}
