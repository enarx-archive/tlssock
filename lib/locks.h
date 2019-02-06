/* vim: set tabstop=8 shiftwidth=2 softtabstop=2 expandtab smarttab colorcolumn=80: */
/*
 * Copyright 2018,2019 Red Hat, Inc.
 *
 * Author: Nathaniel McCallum & Robbie Harwood
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

#define rwhold_auto_t rwhold_t __attribute__((cleanup(rwhold_release)))
#define hold_auto_t hold_t __attribute__((cleanup(hold_release)))

/* Common infrastructure for scope-based locking. */

/* First, rwlocks! */

typedef struct rwlock rwlock_t;
typedef struct rwhold rwhold_t;

rwlock_t *
rwlock_init(void);

void
rwlock_free(rwlock_t *lock);

rwhold_t *
rwlock_rdlock(rwlock_t *lock);

rwhold_t *
rwlock_wrlock(rwlock_t *lock);

void
rwhold_release(rwhold_t **hold);

/* Then mutexes! */

typedef struct mutex mutex_t;
typedef struct hold hold_t;

mutex_t *
mutex_init(void);

void
mutex_free(mutex_t *lock);

hold_t *
mutex_lock(mutex_t *lock);

void
hold_release(hold_t **hold);

