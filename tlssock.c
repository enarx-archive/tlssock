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

#define __str(s) #s
#define _str(s) __str(s)
#define NEXT(name) ((typeof(name) *) dlsym(RTLD_NEXT, _str(name)))

#define ctx_auto_t ctx_t __attribute__((cleanup(release)))

typedef enum {
  UNDEFINED = 0,
  CREATED,
  ACCEPTED,
  CONNECTED,
  ESTABLISHED,
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
  pthread_mutex_t mutex;
  struct {
    state_t state;
    union {
      created_t created;
      accepted_t accepted;
      connected_t connected;
      established_t established;
    };
  } data;
} ctx_t;

static struct {
  size_t size;
  ctx_t *ctx;
} global;

static inline int
err(int errnum)
{
  errno = errnum;
  return -1;
}

static inline ctx_t *
acquire(int fd)
{
  if (fd < 0 || (size_t) fd >= global.size)
    return NULL;
  
  pthread_mutex_lock(&global.ctx[fd].mutex);
  return &global.ctx[fd];
}

static inline void
release(ctx_t **ctx)
{
  if (!ctx || !*ctx)
    return;

  pthread_mutex_unlock(&(*ctx)->mutex);
  *ctx = NULL;
}

static inline void
ctx_reset(ctx_t *ctx)
{
  if (!ctx)
    return;

  switch (ctx->data.state) {
  case ACCEPTED:
    SSL_CTX_free(ctx->data.accepted.ctx);
    break;

  case CONNECTED:
    SSL_CTX_free(ctx->data.connected.ctx);
    free(ctx->data.connected.name);
    break;

  case ESTABLISHED:
    SSL_free(ctx->data.established.ssl);
    break;

  default:
    break;
  }

  memset(&ctx->data, 0, sizeof(ctx->data));
}

int
accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
  return accept4(sockfd, addr, addrlen, 0);
}

int
accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
  ctx_auto_t *ctx = NULL;
  ctx_auto_t *con = NULL;
  SSL_CTX *ssl = NULL;
  int fd;

  ctx = acquire(sockfd);
  if (!ctx)
    return err(EBADFD); // FIXME

  switch (ctx->data.state) {
  case UNDEFINED:
    break;

  case CREATED:
    ssl = SSL_CTX_new(ctx->data.created.method);
    if (!ssl)
      return err(ENOMEM);
    break;

  default:
    return err(EBADFD); // FIXME
  }

  fd = NEXT(accept4)(sockfd, addr, addrlen, flags);
  if (fd < 0) {
    SSL_CTX_free(ssl);
    return fd;
  }

  con = acquire(fd);
  if (!con) {
    SSL_CTX_free(ssl);
    close(fd);
    return err(EBADFD); // FIXME
  }

  ctx_reset(con);

  if (ctx->data.state == CREATED) {
    con->data.state = ACCEPTED;
    con->data.accepted.ctx = ssl;
  }

  return fd;
}

int
close(int fd)
{
  ctx_auto_t *ctx = NULL;

  ctx = acquire(fd);
  if (ctx)
    ctx_reset(ctx);

  return NEXT(close)(fd);
}

int
connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
  ctx_auto_t *ctx = NULL;
  SSL_CTX *ssl = NULL;
  int ret;

  ctx = acquire(sockfd);
  if (!ctx)
    return err(EBADFD); // FIXME

  switch (ctx->data.state) {
  case UNDEFINED:
    break;

  case CREATED:
    ssl = SSL_CTX_new(ctx->data.created.method);
    if (!ssl)
      return err(ENOMEM);

    SSL_CTX_set_verify(ssl, SSL_VERIFY_PEER, NULL);
    break;

  default:
    return err(EBADFD); // FIXME
  }

  ret = NEXT(connect)(sockfd, addr, addrlen);
  if (ret < 0) {
    SSL_CTX_free(ssl);
    return ret;
  }

  if (ctx->data.state == CREATED) {
    ctx->data.state = CONNECTED;
    ctx->data.connected.ctx = ssl;
  }

  return ret;
}

int
dup(int oldfd)
{
  ctx_auto_t *ctx = NULL;

  ctx = acquire(oldfd);
  if (ctx && ctx->data.state != UNDEFINED)
    return err(ENOTSUP);

  return NEXT(dup)(oldfd);
}

int
dup2(int oldfd, int newfd)
{
  ctx_auto_t *ctx = NULL;

  ctx = acquire(oldfd);
  if (ctx && ctx->data.state != UNDEFINED)
    return err(ENOTSUP);

  return NEXT(dup2)(oldfd, newfd);
}

FILE *
fdopen(int fd, const char *mode)
{
  ctx_auto_t *ctx = NULL;

  ctx = acquire(fd);
  if (ctx && ctx->data.state != UNDEFINED) {
    errno = ENOTSUP;
    return NULL;
  }

  return NEXT(fdopen)(fd, mode);
}

int
getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen)
{
  return NEXT(getsockopt)(sockfd, level, optname, optval, optlen);
}

ssize_t
read(int fd, void *buf, size_t count)
{
  return NEXT(read)(fd, buf, count);
}

ssize_t
recv(int sockfd, void *buf, size_t len, int flags)
{
  return NEXT(recv)(sockfd, buf, len, flags);
}

ssize_t
recvfrom(int sockfd, void *buf, size_t len, int flags,
         struct sockaddr *src_addr, socklen_t *addrlen)
{
  ctx_auto_t *ctx = NULL;

  ctx = acquire(sockfd);
  if (ctx && ctx->data.state != UNDEFINED)
    return err(ENOTSUP);

  return NEXT(recvfrom)(sockfd, buf, len, flags, src_addr, addrlen);
}

ssize_t
recvmsg(int sockfd, struct msghdr *msg, int flags)
{
  ctx_auto_t *ctx = NULL;

  ctx = acquire(sockfd);
  if (ctx && ctx->data.state != UNDEFINED)
    return err(ENOTSUP);

  return NEXT(recvmsg)(sockfd, msg, flags);
}

ssize_t
send(int sockfd, const void *buf, size_t len, int flags)
{
  return NEXT(send)(sockfd, buf, len, flags);
}

ssize_t
sendto(int sockfd, const void *buf, size_t len, int flags,
       const struct sockaddr *dest_addr, socklen_t addrlen)
{
  ctx_auto_t *ctx = NULL;

  ctx = acquire(sockfd);
  if (ctx && ctx->data.state != UNDEFINED)
    return err(ENOTSUP);

  return NEXT(sendto)(sockfd, buf, len, flags, dest_addr, addrlen);
}

ssize_t
sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
  ctx_auto_t *ctx = NULL;

  ctx = acquire(sockfd);
  if (ctx && ctx->data.state != UNDEFINED)
    return err(ENOTSUP);

  return NEXT(sendmsg)(sockfd, msg, flags);
}

int
setsockopt(int sockfd, int level, int optname,
           const void *optval, socklen_t optlen)
{
  tls_opt_t opt = optname;
  ctx_auto_t *ctx = NULL;

  if (level != PROT_TLS)
    return NEXT(setsockopt)(sockfd, level, optname, optval, optlen);

  ctx = acquire(sockfd);
  if (!ctx)
    return err(EBADFD); // FIXME

  switch (ctx->data.state) {
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

      ssl = SSL_new(ctx->data.connected.ctx);
      if (!ssl)
        return err(ENOMEM);

      if (SSL_set_tlsext_host_name(ssl, ctx->data.connected.name) != 0) {
        SSL_free(ssl);
        return err(EINVAL); // FIXME
      }

      SSL_CTX_free(ctx->data.accepted.ctx);
      ctx->data.state = ESTABLISHED;
      ctx->data.established.ssl = ssl;

      ret = SSL_connect(ssl);
      if (ret != 1) {
        switch (SSL_get_error(ssl, ret)) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
          return err(EINPROGRESS); // FIXME

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
      ctx->data.connected.name = strndup(optval, optlen);
      return ctx->data.connected.name ? 0 : -1;

    case TLS_OPT_SELF_NAME:
    case TLS_OPT_PEER_CERT:
      return err(ENOTSUP); // FIXME

    default:
      return err(EINVAL); // FIXME
    }

  default:
    return err(EBADFD); // FIXME
  }
}

int
shutdown(int sockfd, int how)
{
  ctx_auto_t *ctx = NULL;

  ctx = acquire(sockfd);
  if (ctx && ctx->data.state != UNDEFINED)
    return err(ENOTSUP);

  return NEXT(shutdown)(sockfd, how);
}

int
socket(int domain, int type, int protocol)
{
  const SSL_METHOD *method = NULL;
  ctx_auto_t *ctx = NULL;
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

  ctx = acquire(fd);
  if (!ctx) {
    close(fd);
    return err(EMFILE);
  }

  ctx_reset(ctx);

  if (protocol == PROT_TLS) {
    ctx->data.created.method = method;
    ctx->data.state = CREATED;
  }

  return fd;
}

ssize_t
write(int fd, const void *buf, size_t count)
{
  return NEXT(write)(fd, buf, count);
}

static void __attribute__((constructor))
constructor(void)
{
  long max = sysconf(_SC_OPEN_MAX);
  if (max < 0)
    abort();

  global.size = max;
  global.ctx = calloc(max, sizeof(ctx_t));
  if (global.ctx == NULL)
    abort();

  for (size_t i = 0; i < global.size; i++) {
    if (pthread_mutex_init(&global.ctx[i].mutex, NULL) != 0)
      abort();
  }
}

static void __attribute__((destructor))
destructor(void)
{
  for (size_t i = 0; i < global.size; i++) {
    pthread_mutex_lock(&global.ctx[i].mutex);
    ctx_reset(&global.ctx[i]);
    pthread_mutex_unlock(&global.ctx[i].mutex);
    pthread_mutex_destroy(&global.ctx[i].mutex);
  }

  free(global.ctx);
}
