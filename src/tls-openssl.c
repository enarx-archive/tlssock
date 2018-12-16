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

#include <openssl/ssl.h>
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

static BIO_METHOD *stream = NULL;
static BIO_METHOD *dgram = NULL;

typedef struct {
  pthread_rwlock_t lock;
} lock_t;

struct tls {
  lock_t lock;
  size_t ref;

  const void *misc;
  SSL *ssl;
  int fd;

  union {
    tls_opt_psk_srv_f srv;
    tls_opt_psk_clt_f clt;
  } psk;
};

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
tls_new(int fd, bool client)
{
  SSL_CTX *ctx = NULL;
  tls_t *tls = NULL;
  BIO *bio = NULL;
  int protocol;
  int domain;
  int type;
  int ret;

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

  ctx = SSL_CTX_new(type == SOCK_STREAM ? TLS_method() : DTLS_method());
  bio = BIO_new(type == SOCK_STREAM ? stream : dgram);
  if (!ctx || !bio) {
    SSL_CTX_free(ctx);
    BIO_free(bio);
    free(tls);
    errno = ENOMEM;
    return NULL;
  }

  tls->ssl = SSL_new(ctx);
  BIO_set_data(bio, tls);
  SSL_CTX_free(ctx);
  if (!tls->ssl) {
    BIO_free(bio);
    free(tls);
    errno = ENOMEM;
    return NULL;
  } else {
    SSL_set_bio(tls->ssl, bio, bio);
  }

  ret = pthread_rwlock_init(&tls->lock.lock, NULL);
  if (ret != 0 || SSL_set_ex_data(tls->ssl, 0, tls) != 1) {
    SSL_free(tls->ssl);
    free(tls);
    errno = ret;
    return NULL;
  }

  if (client)
    SSL_set_connect_state(tls->ssl);
  else
    SSL_set_accept_state(tls->ssl);

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

    SSL_free(tls->ssl);
  }

  pthread_rwlock_destroy(&tls->lock.lock);
  memset(tls, 0, sizeof(*tls));
  free(tls);
  return NULL;
}

bool
tls_is_client(tls_t *tls)
{
  lock_auto_t *lock = rdlock(tls);
  return !SSL_is_server(tls->ssl);
}

static int
o2e(tls_t *tls, int ret)
{
  switch (SSL_get_error(tls->ssl, ret)) {
  case SSL_ERROR_WANT_CONNECT:
  case SSL_ERROR_ZERO_RETURN:
  case SSL_ERROR_WANT_ACCEPT:
    errno = ENOTCONN; // FIXME
    return -1;

  case SSL_ERROR_WANT_WRITE:
  case SSL_ERROR_WANT_READ:
    errno = EAGAIN; // FIXME
    return -1;

  case SSL_ERROR_SYSCALL:
    return -1; // errno already set (I think...)

  default:
    errno = EIO; // FIXME
    return -1;
  }
}

ssize_t
tls_read(tls_t *tls, void *buf, size_t count)
{
  lock_auto_t *lock = rdlock(tls);
  size_t bytes = 0;
  int ret;

  ret = SSL_read_ex(tls->ssl, buf, count, &bytes);
  if (ret > 0)
    return bytes;

  return o2e(tls, ret);
}

ssize_t
tls_write(tls_t *tls, const void *buf, size_t count)
{
  lock_auto_t *lock = rdlock(tls);
  size_t bytes = 0;
  int ret;

  ret = SSL_write_ex(tls->ssl, buf, count, &bytes);
  if (ret > 0)
    return bytes;

  return o2e(tls, ret);
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

static int
handshake(tls_t *tls, const void *optval, socklen_t optlen)
{
  int ret;

  ret = SSL_do_handshake(tls->ssl);
  if (ret == 1)
    return 0;

  return o2e(tls, ret);
}

struct tls_opt_psk_clt {
  unsigned int imax;
  unsigned int pmax;
  unsigned int len;
  uint8_t *psk;
  char *id;
};

struct tls_opt_psk_srv {
  const unsigned int max;
  unsigned char *psk;
  unsigned int len;
};

static int
psk_clt_cb(tls_opt_psk_clt_t *clt, const char *username,
           const uint8_t *key, size_t keylen)
{
  if (strlen(username) >= clt->imax)
    return -1;

  if (keylen > clt->pmax)
    return -1;

  memcpy(clt->psk, key, keylen);
  strcpy(clt->id, username);
  clt->len = keylen;
  return 0;
}

static int
psk_srv_cb(tls_opt_psk_srv_t *srv, const uint8_t *key, size_t keylen)
{
  if (keylen > srv->max)
    return -1;

  memcpy(srv->psk, key, keylen);
  srv->len = keylen;
  return 0;
}

static unsigned int
psk_clt(SSL *ssl, const char *hint, char *id, unsigned int imax,
        unsigned char *psk, unsigned int pmax)
{
  tls_opt_psk_clt_t clt = { .pmax = pmax, .imax = imax, .psk = psk, .id = id };
  tls_t *tls = SSL_get_ex_data(ssl, 0);
  tls->psk.clt(&clt, tls->misc, psk_clt_cb);
  return clt.len;
}

static unsigned int
psk_srv(SSL *ssl, const char *identity, unsigned char *psk,
        unsigned int max_psk_len)
{
  tls_opt_psk_srv_t srv = { max_psk_len, psk, 0 };
  tls_t *tls = BIO_get_data(SSL_get_rbio(ssl));
  tls->psk.srv(&srv, tls->misc, identity, psk_srv_cb);
  return srv.len;
}

static int
psk(tls_t *tls, const void *optval, socklen_t optlen)
{
  if (tls_is_client(tls)) {
    SSL_set_psk_client_callback(tls->ssl, optval ? psk_clt : NULL);
    tls->psk.clt = optval;
  } else {
    SSL_set_psk_server_callback(tls->ssl, optval ? psk_srv : NULL);
    tls->psk.srv = optval;
  }

  return 0;
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

static long
bio_ctrl(BIO *bio, int cmd, long iarg, void *parg)
{
  switch (cmd) {
  case BIO_CTRL_FLUSH:
    fsync((int) (intptr_t) BIO_get_data(bio));
    return 1;

  default:
    return 0;
  }
}

static int
bio_read_ex(BIO *bio, char *buf, size_t cnt, size_t *bytes)
{
  tls_t *tls = BIO_get_data(bio);
  ssize_t ret;

  ret = NEXT(read)(tls->fd, buf, cnt);
  if (ret <= 0)
    return 0;

  *bytes = ret;
  return 1;
}

static int
bio_write_ex(BIO *bio, const char *buf, size_t cnt, size_t *bytes)
{
  tls_t *tls = BIO_get_data(bio);
  ssize_t ret;

  ret = NEXT(write)(tls->fd, buf, cnt);
  if (ret <= 0)
    return 0;

  *bytes = ret;
  return 1;
}

static void __attribute__((constructor))
constructor(void)
{
  int sid = BIO_get_new_index() | BIO_TYPE_SOURCE_SINK | BIO_TYPE_DESCRIPTOR;
  int did = BIO_get_new_index() | BIO_TYPE_SOURCE_SINK | BIO_TYPE_DESCRIPTOR;

  stream = BIO_meth_new(sid, "tlssock-stream");
  dgram = BIO_meth_new(did, "tlssock-dgram");

  BIO_meth_set_ctrl(stream, bio_ctrl);
  BIO_meth_set_ctrl(dgram, bio_ctrl);

  BIO_meth_set_read_ex(stream, bio_read_ex);
  BIO_meth_set_read_ex(dgram, bio_read_ex);

  BIO_meth_set_write_ex(stream, bio_write_ex);
  BIO_meth_set_write_ex(dgram, bio_write_ex);
}

static void __attribute__((destructor))
destructor(void)
{
  BIO_meth_free(dgram);
  BIO_meth_free(stream);
}
