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

#define IPPROTO_TLS_CLT 253
#define IPPROTO_TLS_SRV 254

typedef enum {
  TLS_OPT_HANDSHAKE = 0,

  TLS_OPT_PEER_NAME,
  TLS_OPT_PEER_CERT,

  TLS_OPT_SELF_NAME,
  TLS_OPT_SELF_CERT,
} tls_opt_t;
