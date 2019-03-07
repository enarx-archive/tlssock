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

#pragma once

#include <stdbool.h>
#include <sys/socket.h>

typedef struct gss gss_t;
#define gss_auto_t gss_t __attribute__((cleanup(gss_cleanup)))

gss_t *
gss_new(void);

void
gss_cleanup(gss_t **gss);

gss_t *
gss_incref(gss_t *gss);

gss_t *
gss_decref(gss_t *gss);

ssize_t
gss_recv(gss_t *gss, int fd, void *buf, size_t count);

ssize_t
gss_send(gss_t *gss, int fd, void *buf, size_t count);

int
gss_setsockopt(gss_t *gss, int fd, int optname, const void *optval,
               socklen_t optlen);

int
gss_getsockopt(gss_t *gss, int fd, int optname, void *optval,
               socklen_t *optlen);
