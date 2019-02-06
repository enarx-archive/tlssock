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
#include <stdlib.h>
#include <pthread.h>

struct rwhold {
  pthread_rwlock_t lock;
};

struct rwlock {
  rwhold_t hold;
};

struct hold {
  pthread_mutex_t lock;
};

struct mutex {
  hold_t hold;
};

rwlock_t *
rwlock_init(void)
{
  rwlock_t *lock = NULL;
  int ret = 0;

  lock = malloc(sizeof(*lock));
  if (!lock)
    return NULL;

  ret = pthread_rwlock_init(&lock->hold.lock, NULL);
  if (ret != 0) {
    free(lock);
    errno = ret;
    return NULL;
  }

  return lock;
}

void
rwlock_free(rwlock_t *lock)
{
  if (!lock)
    return;

  pthread_rwlock_destroy(&lock->hold.lock);
  free(lock);
}

rwhold_t *
rwlock_rdlock(rwlock_t *lock)
{
  if (!lock)
    return NULL;

  int ret = pthread_rwlock_rdlock(&lock->hold.lock);
  if (ret != 0) {
    errno = ret;
    return NULL;
  }

  return &lock->hold;
}

rwhold_t *
rwlock_wrlock(rwlock_t *lock)
{
  if (!lock)
    return NULL;

  int ret = pthread_rwlock_wrlock(&lock->hold.lock);
  if (ret != 0) {
    errno = ret;
    return NULL;
  }

  return &lock->hold;
}

void
rwhold_release(rwhold_t **hold)
{
  if (hold && *hold) {
    pthread_rwlock_unlock(&(*hold)->lock);
    *hold = NULL;
  }
}

mutex_t *
mutex_init(void)
{
  mutex_t *lock = NULL;
  int ret = 0;

  lock = malloc(sizeof(*lock));
  if (!lock)
    return NULL;

  ret = pthread_mutex_init(&lock->hold.lock, NULL);
  if (ret != 0) {
    free(lock);
    errno = ret;
    return NULL;
  }

  return lock;
}

void
mutex_free(mutex_t *lock)
{
  if (!lock)
    return;

  pthread_mutex_destroy(&lock->hold.lock);
  free(lock);
}

hold_t *
mutex_lock(mutex_t *lock)
{
  if (!lock)
    return NULL;

  int ret = pthread_mutex_lock(&lock->hold.lock);
  if (ret != 0) {
    errno = ret;
    return NULL;
  }

  return &lock->hold;
}

void
hold_release(hold_t **hold)
{
  if (hold && *hold) {
    pthread_mutex_unlock(&(*hold)->lock);
    *hold = NULL;
  }
}

