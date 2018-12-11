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

  union {
    struct {
      struct {
        gnutls_psk_client_credentials_t cred;
        tls_opt_psk_clt_f func;
      } psk;
    } clt;

    struct {
      struct {
        gnutls_psk_server_credentials_t cred;
        tls_opt_psk_srv_f func;
      } psk;
    } srv;
  };
} creds_t;

struct tls {
  lock_t lock;
  size_t ref;

  gnutls_session_t session;
  creds_t creds;
  int flags;
  int fd;

  const void *misc;
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
  case GNUTLS_E_SUCCESS:
    return 0;

  case GNUTLS_E_AGAIN:
    errno = EAGAIN;
    return -1;

  case GNUTLS_E_INTERRUPTED:
    errno = EINTR;
    return -1;

  case GNUTLS_E_LARGE_PACKET:
    errno = EMSGSIZE;
    return -1;

  case GNUTLS_E_INSUFFICIENT_CRED:
    errno = EPERM; // FIXME
    return -1;

  default:
    if (!gnutls_error_is_fatal(ret))
      return 0;

    errno = EIO; // FIXME
    return -1;
  }
}

static void
lock_cleanup(lock_t **lock)
{
  if (lock && *lock) {
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

  if (!is_tls_domain(domain)) {
    errno = EINVAL; // FIXME
    return NULL;
  }

  if (!is_tls_type(type)) {
    errno = EINVAL; // FIXME
    return NULL;
  }

  if (!is_tls_inner_protocol(protocol)) {
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

  tls->flags |= type == SOCK_DGRAM ? GNUTLS_DATAGRAM : 0;
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

    if (tls->session)
      gnutls_deinit(tls->session);

    if (tls->creds.cert)
      gnutls_certificate_free_credentials(tls->creds.cert);

    if (tls_is_client(tls)) {
      if (tls->creds.clt.psk.cred)
        gnutls_psk_free_client_credentials(tls->creds.clt.psk.cred);
    } else {
      if (tls->creds.srv.psk.cred)
        gnutls_psk_free_server_credentials(tls->creds.srv.psk.cred);
    }
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

  switch (optname) {
  case TLS_OPT_MISC:
    *((const void **) optval) = tls->misc;
    *optlen = sizeof(void *);
    return 0;

  default:
    errno = ENOSYS; // TODO
    return -1;
  }
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
  int ret = 0;
  int nb = 0;

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
  if (ret & O_NONBLOCK)
    nb = GNUTLS_NONBLOCK;

  ret = gnutls_init(&session, tls->flags | nb);
  if (ret == GNUTLS_E_SUCCESS) {
    gnutls_session_set_ptr(session, tls);
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

  if (tls_is_client(tls)) {
    if (ret == GNUTLS_E_SUCCESS && tls->creds.clt.psk.cred)
      ret = gnutls_credentials_set(session, GNUTLS_CRD_PSK, tls->creds.clt.psk.cred);
  } else {
    if (ret == GNUTLS_E_SUCCESS && tls->creds.srv.psk.cred)
      ret = gnutls_credentials_set(session, GNUTLS_CRD_PSK, tls->creds.srv.psk.cred);
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

struct tls_opt_psk_clt {
  gnutls_datum_t *key;
  char **username;
};

struct tls_opt_psk_srv {
  gnutls_datum_t *key;
};

static int
psk_clt_cb(tls_opt_psk_clt_t *clt, const char *username,
           const uint8_t *key, size_t keylen)
{
  if (*clt->username)
    gnutls_free(*clt->username);

  if (clt->key->data)
    gnutls_free(clt->key->data);

  *clt->username = gnutls_strdup(username);
  if (!*clt->username)
    return -1;

  clt->key->data = gnutls_malloc(keylen);
  if (!clt->key->data)
    return -1;

  memcpy(clt->key->data, key, keylen);
  return 0;
}

static int
psk_srv_cb(tls_opt_psk_srv_t *srv, const uint8_t *key, size_t keylen)
{
  if (srv->key->data)
    gnutls_free(srv->key->data);

  srv->key->data = gnutls_malloc(keylen);
  if (!srv->key->data)
    return -1;

  memcpy(srv->key->data, key, keylen);
  return 0;
}

static int
psk_clt(gnutls_session_t session, char **username, gnutls_datum_t *key)
{
  tls_t *tls = gnutls_session_get_ptr(session);
  tls_opt_psk_clt_t clt = { key, username };
  int ret;

  ret = tls->creds.clt.psk.func(&clt, tls->misc, psk_clt_cb);
  if (ret == 0)
    ret = (*username && key->data) ? 0 : -1;
  return ret;
}

static int
psk_srv(gnutls_session_t session, const char *username, gnutls_datum_t *key)
{
  tls_t *tls = gnutls_session_get_ptr(session);
  tls_opt_psk_srv_t srv = { key };
  int ret;

  ret = tls->creds.srv.psk.func(&srv, tls->misc, username, psk_srv_cb);
  if (ret == 0)
    ret = key->data ? 0 : -1;
  return ret;
}

static int
psk(tls_t *tls, const void *optval, socklen_t optlen)
{
  int ret = GNUTLS_E_SUCCESS;

  if (tls_is_client(tls)) {
    tls->creds.clt.psk.func = optval;

    if (optval) {
      if (!tls->creds.clt.psk.cred)
        ret = gnutls_psk_allocate_client_credentials(&tls->creds.clt.psk.cred);

      if (ret == GNUTLS_E_SUCCESS)
        gnutls_psk_set_client_credentials_function(tls->creds.clt.psk.cred, psk_clt);
    } else {
      if (tls->creds.clt.psk.cred)
        gnutls_psk_free_client_credentials(tls->creds.clt.psk.cred);

      memset(&tls->creds.clt.psk, 0, sizeof(tls->creds.clt.psk));
    }
  } else {
    tls->creds.srv.psk.func = optval;

    if (optval) {
      if (!tls->creds.srv.psk.cred)
        ret = gnutls_psk_allocate_server_credentials(&tls->creds.srv.psk.cred);

      if (ret == GNUTLS_E_SUCCESS)
        gnutls_psk_set_server_credentials_function(tls->creds.srv.psk.cred, psk_srv);
    } else {
      if (tls->creds.srv.psk.cred)
        gnutls_psk_free_server_credentials(tls->creds.srv.psk.cred);

      memset(&tls->creds.srv.psk, 0, sizeof(tls->creds.srv.psk));
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
  case TLS_OPT_MISC: tls->misc = optval; return 0;
  case TLS_OPT_PSK: return psk(tls, optval, optlen);
  default: errno = ENOPROTOOPT; return -1; // FIXME
  }
}
