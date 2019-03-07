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

/*
 * Beyond indicating IPPROTO_GSS at creation, GSSAPI requires only a single
 * setsockopt() on the client to set the server name (and none on the server).
 * To GSSAPI, our clients are always initiators, and our servers are always
 * acceptors.
 */

#define IPPROTO_GSS 254 /* Our protocol (woo!) */

/* Various socket options.  Server name can only be set prior to handshake,
 * and must be set on the client.  These flags can function as a bitmask. */
enum {
  GSS_SERVER_NAME = 1 << 0,
  GSS_HANDSHAKE_CLIENT = 1 << 1,
  GSS_HANDSHAKE_SERVER = 1 << 2,
};
