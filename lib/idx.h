/* vim: set tabstop=8 shiftwidth=2 softtabstop=2 expandtab smarttab colorcolumn=80: */
/*
 * Copyright 2018,2019 Red Hat, Inc.
 *
 * Author: Nathaniel McCallum, Robbie Harwood
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

#include <pthread.h>
#include <stdbool.h>

typedef void *(*ref_cb_fn)(void *);
typedef struct {
  pthread_rwlock_t rwl;
  void **elts;
  size_t len;

  ref_cb_fn incref;
  ref_cb_fn decref;
} idx_t;

bool
idx_set(idx_t *idx, int fd, void *elt, void *already);

void *
idx_get(idx_t *idx, int fd);

bool
idx_del(idx_t *idx, int fd);

void
idx_destroy(idx_t *idx);
