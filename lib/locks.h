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

#include <pthread.h>

/* Common infrastructure for scope-based locking. */

typedef struct {
  pthread_rwlock_t lock;
} rwlock_t;

int
rwlock_init(rwlock_t *lock);

void
rwlock_cleanup(rwlock_t **lock);

void
rwlock_destroy(rwlock_t *lock);

rwlock_t *
rw_rdlock(rwlock_t *tls);

rwlock_t *
rw_wrlock(rwlock_t *tls);

#define rwlock_auto_t rwlock_t __attribute__((cleanup(rwlock_cleanup)))
