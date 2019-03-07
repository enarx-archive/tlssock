/* vim: set tabstop=8 shiftwidth=2 softtabstop=2 expandtab smarttab colorcolumn=80: */
/*
 * Copyright 2019 Red Hat, Inc.
 *
 * Author: Robbie Harwood
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

#include "gss-internal.h"

#include "buf.h"
#include "gss.h"
#include "locks.h"

#include <arpa/inet.h>
#include <errno.h>
#include <gssapi/gssapi.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

/* 60 second timeout.  Set to -1 to debug handshake. */
#define TIMEOUT 60000

#define GSS_FLAGS (GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG | GSS_C_MUTUAL_FLAG | \
                   GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG)

struct gss {
  /* Take read on all entry; take write for updating ref. */
  rwlock_t *access_lock;
  size_t ref;

  /* Also take buf_lock for all the rest, read or write. */
  mutex_t *buf_lock;
  gss_ctx_id_t ctx;
  gss_name_t acceptor_name;
  dyn_buf inbuf;
  dyn_buf outbuf;
};

/* Log to $KRB5_TRACE, and only when it's set. */
static void
tlog(const char *fmt, ...)
{
  char *tracepath;
  va_list ap;
  FILE *f;

  tracepath = secure_getenv("KRB5_TRACE");
  if (!tracepath || tracepath[0] == '\0')
    return;

  va_start(ap, fmt);

  f = fopen(tracepath, "a");
  vfprintf(f, fmt, ap);
  fflush(f);
  fclose(f);

  va_end(ap);
}

/* Log human-readable GSSAPI errors. */
static void
dump_error(OM_uint32 major, OM_uint32 minor)
{
  OM_uint32 lmajor, lminor, msg_ctx;
  gss_buffer_desc output;
  char *tracepath;

  tracepath = secure_getenv("KRB5_TRACE");
  if (!tracepath || tracepath[0] == '\0')
    return;

  do {
    lmajor = gss_display_status(&lminor, major, GSS_C_GSS_CODE, GSS_C_NO_OID,
                                &msg_ctx, &output);
    if (GSS_ERROR(lmajor)) {
      tlog("gsssock: error: gss_display_status() failed (%d, %d)", lmajor,
           lminor);
      return;
    }
    tlog("gsssock: error: %s\n", output.value);
  } while (msg_ctx);

  do {
    lmajor = gss_display_status(&lminor, minor, GSS_C_MECH_CODE, GSS_C_NO_OID,
                                &msg_ctx, &output);
    if (GSS_ERROR(lmajor)) {
      tlog("gsssock: error: gss_display_status() failed (%d, %d)", lmajor,
           lminor);
      return;
    }
    tlog("gsssock: error: %s\n", output.value);
  } while (msg_ctx);
}

gss_t *
gss_new()
{
  gss_t *gss = calloc(1, sizeof(*gss));
  if (!gss)
    return NULL;

  gss->access_lock = rwlock_init();
  if (!gss->access_lock) {
    free(gss);
    return NULL;
  }

  gss->buf_lock = mutex_init();
  if (!gss->buf_lock) {
    rwlock_free(gss->access_lock);
    free(gss);
    return NULL;
  }

  gss->ref = 1;
  return gss;
}

void
gss_cleanup(gss_t **gss)
{
  if (gss)
    gss_decref(*gss);
}

gss_t *
gss_incref(gss_t *gss)
{
  rwhold_auto_t *rw = NULL;

  if (!gss)
    return NULL;

  rw = rwlock_wrlock(gss->access_lock);
  if (!rw)
    return NULL;

  gss->ref++;
  return gss;
}

gss_t *
gss_decref(gss_t *gss)
{
  OM_uint32 minor;

  if (!gss)
      return NULL;

  {
    rwhold_auto_t *rw = rwlock_wrlock(gss->access_lock);
    if (!rw)
      return NULL;

    gss->ref--;
    if (gss->ref >= 1)
      return gss;
  }

  gss_delete_sec_context(&minor, &gss->ctx, GSS_C_NO_BUFFER);
  rwlock_free(gss->access_lock);
  mutex_free(gss->buf_lock);
  db_free(&gss->inbuf);
  db_free(&gss->outbuf);
  free(gss);
  return NULL;
}

static int
set_acc_name(gss_t *gss, const void *str, socklen_t strlen)
{
  OM_uint32 major, minor;
  gss_buffer_desc name_buf = GSS_C_EMPTY_BUFFER;
  hold_auto_t *m = mutex_lock(gss->buf_lock);

  if (gss->ctx) /* Can't be set once context negotiation has begun */
    goto fail;

  name_buf.value = (void *)str; /* isn't GSSAPI fun? */
  name_buf.length = strlen;
  major = gss_import_name(&minor, &name_buf, GSS_C_NT_HOSTBASED_SERVICE,
                          &gss->acceptor_name);
  if (major == GSS_S_COMPLETE)
    return 0;

  dump_error(major, minor);

fail:
  errno = EINVAL;
  return -1;
}

int
gss_getsockopt(gss_t *gss, int fd, int optname, void *optval,
               socklen_t *optlen)
{
  errno = EINVAL;
  return -1;
}

ssize_t
gss_recv(gss_t *gss, int fd, void *buf, size_t count)
{
  OM_uint32 major, minor;
  gss_buffer_desc input = GSS_C_EMPTY_BUFFER, output = GSS_C_EMPTY_BUFFER;
  int conf = 0, ret;
  uint32_t local_len;
  size_t len_avail;
  rwhold_auto_t *rw = rwlock_rdlock(gss->access_lock);

  if (count == 0)
    return 0;

  {
    hold_auto_t *buf_access = mutex_lock(gss->buf_lock);

    /* check first for an in-progress readout and continue it */
    if (gss->inbuf.offset != 0) {
      ret = db_sink_buf(&gss->inbuf, buf, count);
      tlog("%d: gss_recv(\"%s\")\n", getpid(), buf);
      return ret;
    }

    /* check for packet length */
    len_avail = db_len_avail(&gss->inbuf);
    if (len_avail < 4) {
      ret = db_make_available(&gss->inbuf, fd, 4);
      if (ret <= 0)
        return ret;
      len_avail = 4;
    }

    /* Load full packet.  Arguably, length should be checked here. */
    local_len = ntohl(*(uint32_t *)db_head(&gss->inbuf));
    if (len_avail < local_len + 4) {
      ret = db_make_available(&gss->inbuf, fd, local_len + 4);
      if (ret <= 0)
        return ret;
    }

    input.value = db_head(&gss->inbuf) + 4;
    input.length = local_len;
    major = gss_unwrap(&minor, gss->ctx, &input, &output, &conf, NULL);
    if (major != GSS_S_COMPLETE) {
      errno = minor;
      return -1;
    } else if (conf == 0) {
      errno = EPROTO;
      return -1;
    }

    db_reset(&gss->inbuf);
    /* encrypted is always at least as long as decrypted */
    (void)db_add_bytes(&gss->inbuf, output.value, output.length);
    gss_release_buffer(&minor, &output);

    /* do a readout */
    ret = db_sink_buf(&gss->inbuf, buf, count);
    tlog("%d: gss_recv(\"%s\")\n", getpid(), buf);
    return ret;
  }
}

ssize_t
gss_send(gss_t *gss, int fd, void *buf, size_t count)
{
  OM_uint32 major, minor;
  gss_buffer_desc input, output = GSS_C_EMPTY_BUFFER;
  int conf = 0, ret;
  uint32_t netlen;
  ssize_t sunk;
  rwhold_auto_t *rw = rwlock_rdlock(gss->access_lock);

  if (count == 0)
    return 0;

  tlog("%d: gss_send(\"%s\")\n", getpid(), buf);

  {
    hold_auto_t *buf_access = mutex_lock(gss->buf_lock);

    /* We might only get one write call, so only make one write attempt.
     * It's a violation to call again with different buffer etc. etc. */
    if (db_len_avail(&gss->outbuf)) {
      sunk = db_sink_fd(&gss->outbuf, fd);
      if (sunk < 0)
        return -1;

      if (db_len_avail(&gss->outbuf)) {
        errno = EWOULDBLOCK;
        return -1;
      }
      return count; /* indicate to caller that a full write occurred */
    }

    input.value = buf;
    input.length = count;
    major = gss_wrap(&minor, gss->ctx, 1, GSS_C_QOP_DEFAULT, &input,
                     &conf, &output);
    if (major != GSS_S_COMPLETE) {
      errno = minor;
      return -1;
    } else if (conf == 0) {
      errno = EPROTO;
      return -1;
    }

    netlen = htonl(output.length);
    ret = db_add_bytes(&gss->outbuf, (uint8_t *)&netlen, 4);
    if (ret) {
      gss_release_buffer(&minor, &output);
      return -1;
    }

    ret = db_add_bytes(&gss->outbuf, output.value, output.length);
    if (ret) {
      gss_release_buffer(&minor, &output);
      return -1;
    }

    gss_release_buffer(&minor, &output);

    sunk = db_sink_fd(&gss->outbuf, fd);
    if (sunk < 0)
      return -1;
    if (db_len_avail(&gss->outbuf)) {
      errno = EWOULDBLOCK;
      return -1;
    }
    return count; /* indicates a full write */
  }
}

static short
step_client(gss_t *gss, int fd)
{
  OM_uint32 major, minor, ret_flags;
  gss_buffer_desc input = GSS_C_EMPTY_BUFFER, output = GSS_C_EMPTY_BUFFER;
  uint32_t net_len, local_len;
  int ret;

  if (db_len_avail(&gss->outbuf)) {
    ssize_t sent = db_sink_fd(&gss->outbuf, fd);
    if (sent < 0)
      return -1;
    if (db_len_avail(&gss->outbuf))
      return POLLOUT;
  }

  if (gss->ctx) {
    /* not first call and nothing to send - must be reading */
    size_t len_avail;
    len_avail = db_len_avail(&gss->inbuf);
    if (len_avail < 4) {
      ret = db_make_available(&gss->inbuf, fd, 4);
      if (ret <= 0)
        return ret;
      len_avail = 4;
    }

    local_len = ntohl(*(uint32_t *)db_head(&gss->inbuf));
    if (len_avail < local_len + 4) {
      ret = db_make_available(&gss->inbuf, fd, local_len + 4);
      if (ret <= 0)
        return ret;
    }

    input.value = db_head(&gss->inbuf) + 4;
    input.length = local_len;
  }

  major = gss_init_sec_context(&minor, GSS_C_NO_CREDENTIAL, &gss->ctx,
                               gss->acceptor_name, GSS_C_NO_OID,
                               GSS_FLAGS, 0, GSS_C_NO_CHANNEL_BINDINGS,
                               &input, NULL, &output, &ret_flags, NULL);
  db_reset(&gss->inbuf);
  if (GSS_ERROR(major)) {
    dump_error(major, minor);
    gss_delete_sec_context(&minor, &gss->ctx, NULL);
    errno = EPROTO;
    return -1;
  } else if ((ret_flags & GSS_FLAGS) != GSS_FLAGS) {
    gss_delete_sec_context(&minor, &gss->ctx, NULL);
    errno = EPROTO;
    return -1;
  } else if (output.length == 0) {
    return 0;
  }

  net_len = htonl(output.length);
  ret = db_add_bytes(&gss->outbuf, (uint8_t *)&net_len, 4);
  if (ret < 0) {
    gss_release_buffer(&minor, &output);
    return ret;
  }

  ret = db_add_bytes(&gss->outbuf, output.value, output.length);
  if (ret < 0) {
    gss_release_buffer(&minor, &output);
    return ret;
  }

  return POLLOUT;
}

static short
step_server(gss_t *gss, int fd, bool *complete_next)
{
  OM_uint32 major, minor, ret_flags;
  gss_buffer_desc input, output = GSS_C_EMPTY_BUFFER;
  uint32_t netlen, local_len;
  int ret;
  size_t len_avail;

  if (db_len_avail(&gss->outbuf)) {
    ssize_t sent = db_sink_fd(&gss->outbuf, fd);
    if (sent < 0)
      return -1;
    if (db_len_avail(&gss->outbuf))
      return POLLOUT;
  }
  if (*complete_next)
    return 0;

  len_avail = db_len_avail(&gss->inbuf);
  if (len_avail < 4) {
    ret = db_make_available(&gss->inbuf, fd, 4);
    if (ret <= 0)
      return ret;
    len_avail = 4;
  }

  local_len = ntohl(*(uint32_t *)db_head(&gss->inbuf));
  if (len_avail < local_len + 4) {
    ret = db_make_available(&gss->inbuf, fd, local_len + 4);
    if (ret <= 0)
      return ret;
  }

  input.value = db_head(&gss->inbuf) + 4;
  input.length = local_len;
  major = gss_accept_sec_context(&minor, &gss->ctx, GSS_C_NO_CREDENTIAL,
                                 &input, GSS_C_NO_CHANNEL_BINDINGS,
                                 NULL, NULL, &output, &ret_flags, NULL,
                                 NULL);
  db_reset(&gss->inbuf);
  if (GSS_ERROR(major)) {
    gss_delete_sec_context(&minor, &gss->ctx, NULL);
    errno = EPROTO;
    return -1;
  } else if ((ret_flags & GSS_FLAGS) != GSS_FLAGS) {
    /* Fail earily since it won't work later */
    gss_delete_sec_context(&minor, &gss->ctx, NULL);
    errno = EPROTO;
    return -1;
  } else if (!(major & GSS_S_CONTINUE_NEEDED)) {
    /* rfc2744 technically permits context negotiation to be complete both
     * with and without a packet to be sent. */
    *complete_next = true;
  }
  if (output.length == 0)
    return 0;

  netlen = htonl(output.length);
  ret = db_add_bytes(&gss->outbuf, (uint8_t *)&netlen, 4);
  if (ret < 0) {
    gss_release_buffer(&minor, &output);
    return -1;
  }

  ret = db_add_bytes(&gss->outbuf, output.value, output.length);
  if (ret < 0) {
    gss_release_buffer(&minor, &output);
    return -1;
  }

  gss_release_buffer(&minor, &output);
  return POLLOUT;
}

/*
 * GSSAPI (even in the Kerberos-only case) doesn't limit the number of
 * round-trips for context establishment.  (Usually it's one or two, but you
 * shouldn't actually count on that.)  Both the client and server need to read
 * and write - and with nonblocking sockets, they might get
 * EAGAIN/EWOULDBLOCK.  Kludge around this with poll.  An attacker could send
 * data very slowly one byte at a time here, but that's actually less
 * resource-intensive than just opening a lot of sockets, so don't worry about
 * it.
 */
static int
gss_handshake(gss_t *gss, int fd, bool client)
{
  short sret = 0;
  int pret;
  bool complete_next = false;
  struct pollfd f = { 0 };
  rwhold_auto_t *rw = rwlock_rdlock(gss->access_lock);

  {
    hold_auto_t *buf_access = mutex_lock(gss->buf_lock);

    f.fd = fd;
    while (true) {
      if (client)
        sret = step_client(gss, fd);
      else
        sret = step_server(gss, fd, &complete_next);

      if (sret == 0)
        return 0;
      else if (sret == -1)
        return -1;

      f.events = sret;
      pret = poll(&f, 1, TIMEOUT);
      if (pret == -1) {
        return -1;
      } else if (pret == 0 || f.revents == 0) {
        errno = ETIMEDOUT;
        return -1;
      }
    }
  }
}

int
gss_setsockopt(gss_t *gss, int fd, int optname, const void *optval,
               socklen_t optlen)
{
  int ret = -1;
  rwhold_auto_t *rw = NULL;

  if (!gss)
    goto fail;

  rw = rwlock_rdlock(gss->access_lock);

  if (optname & GSS_SERVER_NAME) {
    if (!optval)
      goto fail;

    ret = set_acc_name(gss, optval, optlen);
    if (ret)
      goto fail;
  }

  if ((optname & GSS_HANDSHAKE_SERVER) && (optname & GSS_HANDSHAKE_CLIENT)) {
    goto fail;
  } else if (optname & GSS_HANDSHAKE_CLIENT) {
    ret = gss_handshake(gss, fd, true);
    if (ret)
      return ret;
  } else if (optname & GSS_HANDSHAKE_SERVER) {
    ret = gss_handshake(gss, fd, false);
    if (ret)
      return ret;
  }

  if (ret == 0)
    return 0;

fail:
  errno = ret;
  return -1;
}
