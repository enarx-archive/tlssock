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

static BIO_METHOD *stream = NULL;
static BIO_METHOD *dgram = NULL;

typedef struct {
  pthread_rwlock_t lock;
} lock_t;

struct tls {
  lock_t lock;
  size_t ref;

  SSL *ssl;
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

ssize_t
tls_read(tls_t *tls, int fd, void *buf, size_t count)
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
tls_write(tls_t *tls, int fd, const void *buf, size_t count)
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
tls_getsockopt(tls_t *tls, int fd, int optname, void *optval, socklen_t *optlen)
{
  errno = ENOSYS; // TODO
  return -1;
}

static unsigned int
psk_clt(SSL *ssl, const char *hint, char *id, unsigned int imax,
        unsigned char *psk, unsigned int pmax)
{
  const tls_handshake_t *hs = SSL_get_ex_data(ssl, 0);
  unsigned int ret = 0;
  uint8_t *k = NULL;
  char *u = NULL;
  ssize_t l = 0;

  l = hs->clt.psk(hs->clt.misc, &u, &k);
  if (l < 0)
    return 0;

  if (strlen(id) < imax && l <= pmax) {
    strcpy(id, u);
    memcpy(psk, k, l);
    ret = l;
  }

  explicit_bzero(u, strlen(u));
  explicit_bzero(k, l);
  free(u);
  free(k);
  return ret;
}

static unsigned int
psk_srv(SSL *ssl, const char *identity, unsigned char *psk,
        unsigned int max_psk_len)
{
  const tls_handshake_t *hs = SSL_get_ex_data(ssl, 0);
  unsigned int ret = 0;
  uint8_t *k = NULL;
  ssize_t l = 0;

  l = hs->srv.psk(hs->srv.misc, identity, &k);
  if (l < 0)
    return 0;

  if (l <= max_psk_len) {
    memcpy(psk, k, l);
    ret = l;
  }

  explicit_bzero(k, l);
  free(k);
  return ret;
}

static SSL *
ssl_new(int fd, bool client)
{
  SSL_CTX *ctx = NULL;
  BIO *bio = NULL;
  SSL *ssl = NULL;
  int type = 0;

  if (getsockopt_int(fd, SOL_SOCKET, SO_TYPE, &type) < 0)
    return NULL;

  ctx = SSL_CTX_new(type == SOCK_STREAM ? TLS_method() : DTLS_method());
  if (!ctx)
    goto error;

  bio = BIO_new(type == SOCK_STREAM ? stream : dgram);
  if (!bio)
    goto error;

  ssl = SSL_new(ctx);
  if (!ssl)
    goto error;

  if (client)
    SSL_set_connect_state(ssl);
  else
    SSL_set_accept_state(ssl);

  BIO_set_data(bio, (void *) (intptr_t) fd);
  SSL_set_bio(ssl, bio, bio);
  SSL_CTX_free(ctx);
  return ssl;

error:
  SSL_CTX_free(ctx);
  BIO_free(bio);
  SSL_free(ssl);

  errno = ENOMEM;
  return NULL;
}

int
tls_handshake(tls_t *tls, int fd, bool client, const tls_handshake_t *hs)
{
  int ret;

  if (!tls->ssl) {
    tls->ssl = ssl_new(fd, client);
    if (!tls->ssl)
      return -1;
  }

  /* Prepare callbacks for the handshake. */
  SSL_set_ex_data(tls->ssl, 0, (void *) hs);
  if (client)
    SSL_set_psk_client_callback(tls->ssl, hs->clt.psk ? psk_clt : NULL);
  else
    SSL_set_psk_server_callback(tls->ssl, hs->srv.psk ? psk_srv : NULL);

  ret = SSL_do_handshake(tls->ssl);

  /* Remove callbacks from the handshake. */
  SSL_set_ex_data(tls->ssl, 0, NULL);
  if (client)
    SSL_set_psk_client_callback(tls->ssl, NULL);
  else
    SSL_set_psk_server_callback(tls->ssl, NULL);

  if (ret == 1)
    return 0;

  return o2e(tls, ret);
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
  ssize_t ret;

  ret = NEXT(read)((int) (intptr_t) BIO_get_data(bio), buf, cnt);
  if (ret <= 0)
    return 0;

  *bytes = ret;
  return 1;
}

static int
bio_write_ex(BIO *bio, const char *buf, size_t cnt, size_t *bytes)
{
  ssize_t ret;

  ret = NEXT(write)((int) (intptr_t) BIO_get_data(bio), buf, cnt);
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

  stream = BIO_meth_new(sid, "tlssocks");
  dgram = BIO_meth_new(did, "tlssockd");

  BIO_meth_set_ctrl(stream, bio_ctrl);
  BIO_meth_set_ctrl(dgram, bio_ctrl);

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
