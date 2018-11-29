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

#define options_auto_t options_t __attribute__((cleanup(options_cleanup)))
#define ctx_auto_t ctx_t __attribute__((cleanup(release)))
#define fd_auto_t fd_t __attribute__((cleanup(fdclose)))

typedef int fd_t;

typedef struct {
  size_t size;
  uint8_t data[];
} buffer_t;

typedef struct {
  buffer_t *root;
  buffer_t *cert;
  buffer_t *key;
  char *name;
} options_t;

typedef struct {
  options_t *opt;
  SSL_CTX *ctx;
  SSL *ssl;
} state_t;

typedef struct {
  pthread_mutex_t mutex;
  state_t state;
} ctx_t;

static struct {
  size_t size;
  ctx_t *ctx;
} global;

static buffer_t *
buffer_dup(const void *data, size_t size)
{
  buffer_t *buf = NULL;
  
  buf = calloc(1, sizeof(buffer_t) + size);
  if (!buf)
    return NULL;
  
  memcpy(buf->data, data, size);
  buf->size = size;

  return buf;
}

static void
buffer_free(buffer_t *buf)
{
  if (!buf)
    return;

  OPENSSL_cleanse(buf, sizeof(*buf) + buf->size);
  free(buf);
}

static void
options_free(options_t *opt)
{
  if (!opt)
    return;

  buffer_free(opt->root);
  buffer_free(opt->cert);
  buffer_free(opt->key);
  free(opt->name);
  free(opt);
}

static void
options_cleanup(options_t **opt)
{
  if (opt)
    options_free(*opt);
}

static void
state_clear(state_t *state)
{
  if (!state)
    return;
  
  options_free(state->opt);
  SSL_free(state->ssl);
  SSL_CTX_free(state->ctx);

  memset(state, 0, sizeof(*state));
}

static inline int
err(int errnum)
{
  errno = errnum;
  return -1;
}

static inline ctx_t *
acquire(int fd)
{
  if (fd < 0 || (size_t) fd >= global.size) {
    errno = EBADFD;
    return NULL;
  }
  
  pthread_mutex_lock(&global.ctx[fd].mutex);
  return &global.ctx[fd];
}

static inline void
release(ctx_t **ctx)
{
  if (!ctx || !*ctx)
    return;
  
  pthread_mutex_unlock(&(*ctx)->mutex);
}

static inline void
fdclose(fd_t *fd)
{
  if (!fd || *fd < 0)
    return;
  
  close(*fd);
}

static inline int
fdsteal(fd_t *fd)
{
  int ret = *fd;
  *fd = -1;
  return ret;
}

int
accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
  return accept4(sockfd, addr, addrlen, 0);
}

int
accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
  return NEXT(accept4)(sockfd, addr, addrlen, flags);
}

int
close(int fd)
{
  ctx_auto_t *ctx = NULL;
  
  ctx = acquire(fd);
  if (ctx)
    state_clear(&ctx->state);

  return NEXT(close)(fd);
}

int
connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
  options_auto_t *opt = NULL;
  ctx_auto_t *ctx = NULL;
  int ret;

  ret = NEXT(connect)(sockfd, addr, addrlen);
  if (ret < 0)
    return ret;
  
  ctx = acquire(sockfd);
  if (!ctx || !ctx->state.ctx)
    return -1;
  
  opt = ctx->state.opt;
  ctx->state.opt = NULL;
  if (!opt || !opt->name)
    return err(EBADFD);

  ctx->state.ssl = SSL_new(ctx->state.ctx);
  if (!ctx->state.ssl)
    return err(ENOMEM); // FIXME

  if (!SSL_set_tlsext_host_name(ctx->state.ssl, opt->name))
    return err(ENOMEM); // FIXME
  
  // TODO: Client Certificate
  // TODO: Root CAs
  
  if (!SSL_set_fd(ctx->state.ssl, sockfd))
    return err(ENOMEM); // FIXME
  
  if (!SSL_connect(ctx->state.ssl))
    return err(EIO); // FIXME
  
  if (!SSL_do_handshake(ctx->state.ssl))
    return err(EIO); // FIXME
  
  return 0;
}

int
dup(int oldfd)
{
  return NEXT(dup)(oldfd);
}

int
dup2(int oldfd, int newfd)
{
  return NEXT(dup2)(oldfd, newfd);
}

FILE *
fdopen(int fd, const char *mode)
{
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
  return NEXT(recvfrom)(sockfd, buf, len, flags, src_addr, addrlen);
}

ssize_t
recvmsg(int sockfd, struct msghdr *msg, int flags)
{
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
  return NEXT(sendto)(sockfd, buf, len, flags, dest_addr, addrlen);
}

ssize_t
sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
  return NEXT(sendmsg)(sockfd, msg, flags);
}

int
setsockopt(int sockfd, int level, int optname,
           const void *optval, socklen_t optlen)
{
  ctx_auto_t *ctx = NULL;

  if (level != PROT_TLS)
    return NEXT(setsockopt)(sockfd, level, optname, optval, optlen);

  ctx = acquire(sockfd);
  if (!ctx)
    return -1;
  
  if (!ctx->state.opt)
    return err(EBADFD); // FIXME (correct error?)
  
  switch (optname) {
  case TLS_SELF_NAME:
    ctx->state.opt->name = strndup(optval, optlen);
    return ctx->state.opt->name ? 0 : -1;

  case TLS_SELF_CERT:
    ctx->state.opt->cert = buffer_dup(optval, optlen);
    return ctx->state.opt->cert ? 0 : -1;

  case TLS_SELF_KEY:
    ctx->state.opt->key = buffer_dup(optval, optlen);
    return ctx->state.opt->key ? 0 : -1;

  default:
    return err(ENOPROTOOPT); // FIXME (correct error?)
  }
}

int
shutdown(int sockfd, int how)
{
  return NEXT(shutdown)(sockfd, how);
}

int
socket(int domain, int type, int protocol)
{
  const SSL_METHOD *method = NULL;
  ctx_auto_t *ctx = NULL;
  fd_auto_t fd = -1;

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
  if (!ctx)
    return err(EMFILE);

  state_clear(&ctx->state);

  if (protocol == PROT_TLS) {
    ctx->state.opt = calloc(1, sizeof(options_t));
    if (!ctx->state.opt)
      return -1;
    
    ctx->state.ctx = SSL_CTX_new(method);
    if (!ctx->state.ctx) {
      state_clear(&ctx->state);
      return err(ENOMEM);
    }
  }

  return fdsteal(&fd);
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
    state_clear(&global.ctx[i].state);
    pthread_mutex_unlock(&global.ctx[i].mutex);
    pthread_mutex_destroy(&global.ctx[i].mutex);
  }

  free(global.ctx);
}
