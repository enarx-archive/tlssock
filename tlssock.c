/* 
 * Copyright 2018 Red Hat, Inc.
 * 
 * Author: Nathaniel McCallum
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE X CONSORTIUM BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * Except as contained in this notice, the name(s) of the above copyright
 * holders shall not be used in advertising or otherwise to promote the sale,
 * use or other dealings in this Software without prior written
 * authorization.
 */

#define _GNU_SOURCE
#include "tlssock.h"

#include <openssl/ssl.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

#define __str(s) #s
#define _str(s) __str(s)
#define NEXT(name) ((typeof(name) *) dlsym(RTLD_NEXT, _str(name)))

#define tls_auto_t tls_t __attribute__((cleanup(tls_rel)))

typedef enum {
  UNDEFINED = 0,
  CREATED,
  ACCEPTED,
  CONNECTED,
  ESTABLISHED,
  SHUTDOWN,
} state_t;

typedef struct {
  const SSL_METHOD *method;
} created_t;

typedef struct {
  SSL_CTX *ctx;
} accepted_t;

typedef struct {
  SSL_CTX *ctx;
  char *name;
} connected_t;

typedef struct {
  SSL *ssl;
} established_t;

typedef struct {
  SSL *ssl;
} shutdown_t;

typedef struct {
  state_t state;

  union {
    created_t created;
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
  case CREATED:
    break;

  case ACCEPTED:
    SSL_CTX_free(tls->accepted.ctx);
    break;

  case CONNECTED:
    SSL_CTX_free(tls->connected.ctx);
    free(tls->connected.name);
    break;

  case ESTABLISHED:
    SSL_free(tls->established.ssl);
    break;

  case SHUTDOWN:
    SSL_free(tls->shutdown.ssl);
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

  if (idx.len < (unsigned int) fd) {
    ent_t **ent = NULL;
    size_t len = 0;

    len = (fd + BLOCK - 1) / BLOCK * BLOCK;
    ent = realloc(idx.ent, sizeof(ent_t*) * len);
    if (!ent) {
      pthread_rwlock_unlock(&idx.rwl);
      return NULL;
    }

    memset(&idx.ent[idx.len], 0, sizeof(ent_t*) * (len - idx.len));
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

  if (idx.len < (unsigned int) fd) {
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
  int ret = 0;

  switch (tls->state) {
  case ESTABLISHED:
    break;

  case UNDEFINED:
  case CREATED:
  case ACCEPTED:
  case CONNECTED:
  case SHUTDOWN:
    return err(EBADFD); // FIXME
  }

  if (count > INT_MAX)
    return err(EINVAL); // FIXME

  ret = SSL_read(tls->established.ssl, buf, count);
  if (ret > 0)
    return ret;

  switch (SSL_get_error(tls->established.ssl, ret)) {
  case SSL_ERROR_WANT_READ:
  case SSL_ERROR_WANT_WRITE:
    return err(EAGAIN); // FIXME

  // TODO: others

  default:
    return err(EIO); // FIXME
  }
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
  case ACCEPTED:
  case CONNECTED:
  case SHUTDOWN:
    return err(EBADFD); // FIXME
  }

  if (count > INT_MAX)
    return err(EINVAL); // FIXME

  ret = SSL_write(tls->established.ssl, buf, count);
  if (ret <= 0)
    return ret;

  switch (SSL_get_error(tls->established.ssl, ret)) {
  case SSL_ERROR_WANT_READ:
  case SSL_ERROR_WANT_WRITE:
    return err(EAGAIN); // FIXME

  // TODO: others

  default:
    return err(EIO); // FIXME
  }
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
  SSL_CTX *ssl = NULL;
  int fd;

  tls = tls_get(sockfd, pthread_rwlock_rdlock);
  if (!tls)
    return -1;

  switch (tls->state) {
  case UNDEFINED:
    break;

  case CREATED:
    ssl = SSL_CTX_new(tls->created.method);
    if (!ssl)
      return err(ENOMEM);
    break;

  case ACCEPTED:
  case SHUTDOWN:
  case CONNECTED:
  case ESTABLISHED:
    return err(EBADFD); // FIXME
  }

  fd = NEXT(accept4)(sockfd, addr, addrlen, flags);
  if (fd < 0) {
    SSL_CTX_free(ssl);
    return fd;
  }

  con = tls_new(fd);
  if (!con) {
    SSL_CTX_free(ssl);
    close(fd);
    return -1;
  }

  if (tls->state == CREATED) {
    con->state = ACCEPTED;
    con->accepted.ctx = ssl;
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
  SSL_CTX *ctx = NULL;
  int ret;

  tls = tls_get(sockfd, pthread_rwlock_rdlock);
  if (!tls)
    return -1;

  switch (tls->state) {
  case UNDEFINED:
    return NEXT(connect)(sockfd, addr, addrlen);

  case CREATED:
    ctx = SSL_CTX_new(tls->created.method);
    if (!ctx)
      return err(ENOMEM);

    ret = NEXT(connect)(sockfd, addr, addrlen);
    if (ret < 0) {
      SSL_CTX_free(ctx);
      return ret;
    }

    tls->state = CONNECTED;
    tls->connected.ctx = ctx;

    return ret;

  case ACCEPTED:
  case SHUTDOWN:
  case CONNECTED:
  case ESTABLISHED:
    return err(EBADFD); // FIXME
  }

  abort();
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

int
setsockopt(int sockfd, int level, int optname,
           const void *optval, socklen_t optlen)
{
  tls_auto_t *tls = NULL;
  tls_opt_t opt = optname;

  if (level != PROT_TLS)
    return NEXT(setsockopt)(sockfd, level, optname, optval, optlen);

  tls = tls_get(sockfd, pthread_rwlock_rdlock);
  if (!tls)
    return -1;

  switch (tls->state) {
  case ACCEPTED:
    switch (opt) {
    case TLS_OPT_HANDSHAKE:
      return err(ENOSYS); // TODO

    case TLS_OPT_SELF_KEY:
      return err(ENOSYS); // TODO

    case TLS_OPT_SELF_CERT:
      return err(ENOSYS); // TODO

    case TLS_OPT_ROOT_CERT:
      return err(ENOSYS); // TODO

    case TLS_OPT_SELF_NAME:
    case TLS_OPT_PEER_NAME:
    case TLS_OPT_PEER_CERT:
      return err(ENOTSUP); // FIXME

    default:
      return err(EINVAL); // FIXME
    }

  case CONNECTED:
    switch (opt) {
    case TLS_OPT_HANDSHAKE: {
      SSL *ssl = NULL;
      int ret = -1;

      if (optval != NULL)
        return err(EINVAL);

      SSL_CTX_set_verify(tls->connected.ctx, SSL_VERIFY_PEER, NULL);

      ssl = SSL_new(tls->connected.ctx);
      if (!ssl)
        return err(ENOMEM);

      if (SSL_set_tlsext_host_name(ssl, tls->connected.name) != 0) {
        SSL_free(ssl);
        return err(EINVAL); // FIXME
      }

      SSL_CTX_free(tls->accepted.ctx);
      tls->state = ESTABLISHED;
      tls->established.ssl = ssl;

      ret = SSL_connect(ssl);
      if (ret != 1) {
        switch (SSL_get_error(ssl, ret)) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
          return err(EAGAIN); // FIXME

        default:
          return err(ENOKEY); // FIXME
        }
      }

      if (SSL_do_handshake(ssl) != 0)
        return err(EINVAL); // FIXME

      // TODO: certificate validation

      return 0;
    }

    case TLS_OPT_SELF_KEY:
      return err(ENOSYS); // TODO

    case TLS_OPT_SELF_CERT:
      return err(ENOSYS); // TODO

    case TLS_OPT_ROOT_CERT:
      return err(ENOSYS); // TODO

    case TLS_OPT_PEER_NAME:
      tls->connected.name = strndup(optval, optlen);
      return tls->connected.name ? 0 : -1;

    case TLS_OPT_SELF_NAME:
    case TLS_OPT_PEER_CERT:
      return err(ENOTSUP); // FIXME

    default:
      return err(EINVAL); // FIXME
    }

  case CREATED:
  case SHUTDOWN:
  case UNDEFINED:
  case ESTABLISHED:
    return err(EBADFD); // FIXME
  }

  abort();
}

int
shutdown(int sockfd, int how)
{
  tls_auto_t *tls = NULL;
  int ret;

  tls = tls_get(sockfd, pthread_rwlock_rdlock);
  if (!tls)
    return -1;

  switch (tls->state) {
  case ESTABLISHED:
  case SHUTDOWN:
    if (how != SHUT_RDWR)
      return err(EINVAL);

    if (tls->state == ESTABLISHED) {
      ret = SSL_shutdown(tls->established.ssl);
      if (ret < 0) {
        switch (SSL_get_error(tls->established.ssl, ret)) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
          return err(EAGAIN); // FIXME

        // TODO: others

        default:
          return err(EIO); // FIXME
        }
      }

      tls->shutdown.ssl = tls->established.ssl;
      tls->state = SHUTDOWN;
    }

    return NEXT(shutdown)(sockfd, how);

  case ACCEPTED:
  case CONNECTED:
    if (how != SHUT_RDWR)
      return err(EINVAL);

    tls_clr(tls);
    return NEXT(shutdown)(sockfd, how);

  case CREATED:
    return err(ENOTCONN);

  case UNDEFINED:
    return NEXT(shutdown)(sockfd, how);
  }

  abort();
}

int
socket(int domain, int type, int protocol)
{
  const SSL_METHOD *method = NULL;
  tls_auto_t *tls = NULL;
  int fd = -1;

  if (protocol == PROT_TLS) {
    switch (domain) {
    case AF_INET6: break;
    case AF_INET: break;
    default: return err(EPROTONOSUPPORT);
    }

    switch (type) {
    case SOCK_STREAM: method = TLS_method(); break;
    case SOCK_DGRAM: method = DTLS_method(); break;
    default: return err(EPROTONOSUPPORT);
    }
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
    tls->created.method = method;
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
