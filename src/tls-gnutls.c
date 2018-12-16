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

#include <sys/uio.h>
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

struct tls {
  lock_t lock;
  size_t ref;

  gnutls_session_t session;

  struct {
    union {
      struct {
        gnutls_psk_client_credentials_t psk;
      } clt;

      struct {
        gnutls_psk_server_credentials_t psk;
      } srv;
    };
  } creds;
};

static inline int
g2e(int ret)
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

  case GNUTLS_E_INSUFFICIENT_CREDENTIALS:
    errno = EACCES; // FIXME
    return -1;

  default:
    if (!gnutls_error_is_fatal(ret))
      return ret;

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
  int ret;

  if (!tls)
    return NULL;

  ret = pthread_rwlock_rdlock(&tls->lock.lock);
  if (ret != 0) {
    errno = ret;
    return NULL;
  }

  return &tls->lock;
}

static lock_t *
wrlock(tls_t *tls)
{
  int ret;

  if (!tls)
    return NULL;

  ret = pthread_rwlock_wrlock(&tls->lock.lock);
  if (ret != 0) {
    errno = ret;
    return NULL;
  }

  return &tls->lock;
}

tls_t *
tls_new(void)
{
  tls_t *tls = NULL;
  int ret;

  tls = calloc(1, sizeof(*tls));
  if (!tls)
    return NULL;

  ret = pthread_rwlock_init(&tls->lock.lock, NULL);
  if (ret != 0) {
    free(tls);
    errno = ret;
    return NULL;
  }

  tls->ref = 1;
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

static void
tls_creds_clear(tls_t *tls, bool client)
{
  if (tls->session)
    gnutls_credentials_clear(tls->session);

  if (client) {
    if (tls->creds.clt.psk)
      gnutls_psk_free_client_credentials(tls->creds.clt.psk);
    tls->creds.clt.psk = NULL;
  } else {
    if (tls->creds.srv.psk)
      gnutls_psk_free_server_credentials(tls->creds.srv.psk);
    tls->creds.srv.psk = NULL;
  }
}

static void
tls_clear(tls_t *tls)
{
  if (!tls || !tls->session)
    return;

  tls_creds_clear(tls, gnutls_session_get_flags(tls->session) & GNUTLS_CLIENT);
  gnutls_deinit(tls->session);
  tls->session = NULL;
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

    tls_clear(tls);
  }

  pthread_rwlock_destroy(&tls->lock.lock);
  memset(tls, 0, sizeof(*tls));
  return NULL;
}

ssize_t
tls_read(tls_t *tls, int fd, void *buf, size_t count)
{
  lock_auto_t *lock = rdlock(tls);
  return g2e(gnutls_record_recv(tls->session, buf, count));
}

ssize_t
tls_write(tls_t *tls, int fd, const void *buf, size_t count)
{
  lock_auto_t *lock = rdlock(tls);
  return g2e(gnutls_record_send(tls->session, buf, count));
}

int
tls_getsockopt(tls_t *tls, int fd, int optname, void *optval, socklen_t *optlen)
{
  errno = ENOSYS; // TODO
  return -1;
}

static ssize_t
pull_func(gnutls_transport_ptr_t ptr, void *buf, size_t count)
{
  return NEXT(read)((intptr_t) ptr, buf, count);
}

static ssize_t
push_func(gnutls_transport_ptr_t ptr, const void *buf, size_t count)
{
  return NEXT(write)((intptr_t) ptr, buf, count);
}

static ssize_t
vec_push_func(gnutls_transport_ptr_t ptr, const giovec_t *iov, int iovcnt)
{
  return NEXT(writev)((intptr_t) ptr, iov, iovcnt);
}

static int
pull_timeout_func(gnutls_transport_ptr_t ptr, unsigned int ms)
{
  struct pollfd pfd = { (intptr_t) ptr, POLLIN | POLLPRI };
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
get_flags(int fd, bool client)
{
  int flags = client ? GNUTLS_CLIENT : GNUTLS_SERVER;
  int type = 0;
  int ret = 0;

  ret = fcntl(fd, F_GETFL);
  if (ret < 0)
    return ret;
  if (ret & O_NONBLOCK)
    flags |= GNUTLS_NONBLOCK;

  if (getsockopt_int(fd, SOL_SOCKET, SO_TYPE, &type) < 0)
    return -1;
  if (type == SOCK_DGRAM)
    flags |= GNUTLS_DATAGRAM;

  return flags;
}

static int
psk_clt(gnutls_session_t session, char **username, gnutls_datum_t *key)
{
  const tls_clt_t *clt = gnutls_session_get_ptr(session);
  uint8_t *k = NULL;
  char *u = NULL;
  ssize_t l = 0;

  l = clt->psk(clt->misc, gnutls_psk_client_get_hint(session), &u, &k);
  if (l < 0)
    return -1;

  *username = gnutls_strdup(u);
  key->data = gnutls_malloc(l);
  key->size = l;
  if (key->data)
    memcpy(key->data, k, l);

  explicit_bzero(u, strlen(u));
  explicit_bzero(k, l);
  free(u);
  free(k);

  if (*username && key->data)
    return 0;

  if (*username) {
    explicit_bzero(*username, strlen(*username));
    gnutls_free(*username);
  }

  if (key->data) {
    explicit_bzero(key->data, l);
    gnutls_free(key->data);
  }

  return -1;
}

static int
psk_srv(gnutls_session_t session, const char *username, gnutls_datum_t *key)
{
  const tls_srv_t *srv = gnutls_session_get_ptr(session);
  uint8_t *k = NULL;
  ssize_t l = 0;

  l = srv->psk(srv->misc, username, &k);
  if (l < 0)
    return -1;

  key->data = gnutls_malloc(l);
  key->size = l;
  if (key->data)
    memcpy(key->data, k, l);

  explicit_bzero(k, l);
  free(k);

  return key->data ? 0 : -1;
}

static int
handshake(tls_t *tls, int fd, bool client, const void *optval, socklen_t optlen)
{
  int ret = -1;

  union {
    const tls_clt_t *clt;
    const tls_srv_t *srv;
  } opt = { optval };

  if (!tls->session) {
    static const char *priority = "+ECDHE-PSK:+DHE-PSK:+PSK";
    int flags = 0;

    flags = get_flags(fd, client);
    if (flags < 0)
      return flags;

    ret = g2e(gnutls_init(&tls->session, flags));
    if (ret < 0)
      return ret;

    gnutls_transport_set_int(tls->session, fd);
    gnutls_transport_set_pull_function(tls->session, pull_func);
    gnutls_transport_set_push_function(tls->session, push_func);
    gnutls_transport_set_vec_push_function(tls->session, vec_push_func);
    gnutls_transport_set_pull_timeout_function(tls->session, pull_timeout_func);
    gnutls_handshake_set_timeout(tls->session, 0);

    ret = g2e(gnutls_set_default_priority_append(tls->session, priority, NULL, 0));
    if (ret < 0)
      goto error;
  }

  if (client && opt.clt->psk) {
    ret = g2e(gnutls_psk_allocate_client_credentials(&tls->creds.clt.psk));
    if (ret < 0)
      goto error;

    gnutls_psk_set_client_credentials_function(tls->creds.clt.psk, psk_clt);
    ret = g2e(gnutls_credentials_set(tls->session, GNUTLS_CRD_PSK,
                                     tls->creds.clt.psk));
    if (ret < 0)
      goto error;
  } else if (!client && opt.srv->psk) {
    ret = g2e(gnutls_psk_allocate_server_credentials(&tls->creds.srv.psk));
    if (ret < 0)
      goto error;

    gnutls_psk_set_server_credentials_function(tls->creds.srv.psk, psk_srv);
    ret = g2e(gnutls_credentials_set(tls->session, GNUTLS_CRD_PSK,
                                     tls->creds.srv.psk));
    if (ret < 0)
      goto error;
  }

  gnutls_session_set_ptr(tls->session, (void *) optval);
  ret = g2e(gnutls_handshake(tls->session));
  gnutls_session_set_ptr(tls->session, NULL);
  tls_creds_clear(tls, client);
  if (ret >= 0 || errno == EAGAIN)
    return ret;

error:
  tls_clear(tls);
  return ret;
}

int
tls_setsockopt(tls_t *tls, int fd, int optname,
               const void *optval, socklen_t optlen)
{
  lock_auto_t *lock = wrlock(tls);

  switch (optname) {
  case TLS_CLT_HANDSHAKE:
  case TLS_SRV_HANDSHAKE:
    return handshake(tls, fd, optname == TLS_CLT_HANDSHAKE, optval, optlen);

  default:
    errno = ENOPROTOOPT; // FIXME
    return -1;
  }
}
