/* vim: set tabstop=8 shiftwidth=2 softtabstop=2 expandtab smarttab colorcolumn=80: */
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

#pragma once

#include "tlssock.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <stdbool.h>

#define tls_auto_t tls_t __attribute__((cleanup(tls_cleanup)))

typedef union {
  tls_clt_handshake_t clt;
  tls_srv_handshake_t srv;
} tls_handshake_t;

typedef union {
  tls_handshake_t handshake;
} tls_opt_t;

typedef struct tls tls_t;

tls_t *
tls_new(void);

void
tls_cleanup(tls_t **tls);

tls_t *
tls_incref(tls_t *tls);

tls_t *
tls_decref(tls_t *tls);

ssize_t
tls_read(tls_t *tls, int fd, void *buf, size_t count);

ssize_t
tls_write(tls_t *tls, int fd, const void *buf, size_t count);

int
tls_getsockopt(tls_t *tls, int fd, int optname,
               void *optval, socklen_t *optlen);

int
tls_handshake(tls_t *tls, int fd, bool client, const tls_handshake_t *hs);
