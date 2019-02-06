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

#include "locks.h"

#include <errno.h>
#include <pthread.h>

int
rwlock_init(rwlock_t *lock)
{
  return pthread_rwlock_init(&lock->lock, NULL);
}

void
rwlock_cleanup(rwlock_t **lock)
{
  if (lock && *lock) {
    pthread_rwlock_unlock(&(*lock)->lock);
    *lock = NULL;
  }
}

void
rwlock_destroy(rwlock_t *lock)
{
  pthread_rwlock_destroy(&lock->lock);
}

rwlock_t *
rw_rdlock(rwlock_t *lock)
{
  int ret = pthread_rwlock_rdlock(&lock->lock);
  if (ret != 0) {
    errno = ret;
    return NULL;
  }

  return lock;
}

rwlock_t *
rw_wrlock(rwlock_t *lock)
{
  int ret = pthread_rwlock_wrlock(&lock->lock);
  if (ret != 0) {
    errno = ret;
    return NULL;
  }

  return lock;
}

int
mutex_init(mutex_t *lock)
{
  return pthread_mutex_init(&lock->lock, NULL);
}

void
mutex_cleanup(mutex_t **lock)
{
  if (!lock || !*lock)
    return;
  pthread_mutex_unlock(&(*lock)->lock);
  *lock = NULL;
}

void
mutex_destroy(mutex_t *lock)
{
  pthread_mutex_destroy(&lock->lock);
}

mutex_t *
mutex_lock(mutex_t *lock)
{
  int ret = pthread_mutex_lock(&lock->lock);
  if (ret) {
    errno = ret;
    return NULL;
  }
  return lock;
}
