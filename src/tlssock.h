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

#include <stdint.h>
#include <stddef.h>

#define IPPROTO_TLS_CLT 253
#define IPPROTO_TLS_SRV 254

typedef enum {
  TLS_OPT_HANDSHAKE = 0,

  TLS_OPT_PEER_NAME,
  TLS_OPT_PEER_CERT,

  TLS_OPT_SELF_NAME,
  TLS_OPT_SELF_CERT,

  TLS_OPT_PSK,

  TLS_OPT_MISC,
} tls_opt_t;

typedef struct tls_opt_psk_clt tls_opt_psk_clt_t;
typedef int
(*tls_opt_psk_clt_f)(tls_opt_psk_clt_t *clt, const void *misc,
                     int (*callback)(tls_opt_psk_clt_t *clt,
                                     const char *username,
                                     const uint8_t *key, size_t keylen));

typedef struct tls_opt_psk_srv tls_opt_psk_srv_t;
typedef int
(*tls_opt_psk_srv_f)(tls_opt_psk_srv_t *srv, const void *misc,
                     const char *username,
                     int (callback)(tls_opt_psk_srv_t *srv,
                                    const uint8_t *key, size_t keylen));
