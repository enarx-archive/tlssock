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

#include "idx.h"

#include <pthread.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

static struct {
  pthread_rwlock_t rwl;
  tls_t **tls;
  size_t len;
} idx = { .rwl = PTHREAD_RWLOCK_INITIALIZER };

static long pagesize;

bool
idx_set(int fd, tls_t *tls, tls_t **already)
{
  if (fd < 0)
    return false;

  pthread_rwlock_wrlock(&idx.rwl);

  if (idx.len <= (unsigned int) fd) {
    const int block = pagesize / sizeof(tls_t*);
    tls_t **tmp = NULL;
    size_t len = 0;

    len = (fd + block) / block * block;
    tmp = realloc(idx.tls, sizeof(tls_t*) * len);
    if (!tmp)
      goto error;

    memset(&tmp[idx.len], 0, sizeof(tls_t*) * (len - idx.len));
    idx.len = len;
    idx.tls = tmp;
  }

  if (idx.tls[fd]) {
    if (already) {
      *already = tls_incref(idx.tls[fd]);
      if (*already)
        goto error;
    }

    errno = EALREADY;
    goto error;
  }

  idx.tls[fd] = tls_incref(tls);
  if (!idx.tls[fd])
    goto error;

  pthread_rwlock_unlock(&idx.rwl);
  return true;

error:
  pthread_rwlock_unlock(&idx.rwl);
  return false;
}

tls_t *
idx_get(int fd)
{
  tls_t *tls = NULL;

  if (fd < 0)
    return NULL;

  pthread_rwlock_rdlock(&idx.rwl);

  if (idx.len <= (unsigned int) fd)
    goto error;

  tls = tls_incref(idx.tls[fd]);

error:
  pthread_rwlock_unlock(&idx.rwl);
  return tls_incref(tls);
}

bool
idx_del(int fd)
{
  bool found = false;

  if (fd < 0) {
    errno = EBADF; // FIXME
    return false;
  }

  pthread_rwlock_wrlock(&idx.rwl);

  if (idx.len > (unsigned int) fd && idx.tls[fd]) {
    tls_decref(idx.tls[fd]);
    idx.tls[fd] = NULL;
    found = true;
  }

  pthread_rwlock_unlock(&idx.rwl);

  if (!found)
    errno = ENOENT;

  return found;
}

static void __attribute__((constructor))
constructor(void)
{
  pagesize = sysconf(_SC_PAGESIZE);
  if (pagesize < 0)
    abort();
  if (pagesize % sizeof(void*) != 0)
    abort();
}

static void __attribute__((destructor))
destructor(void)
{
  pthread_rwlock_wrlock(&idx.rwl);

  for (size_t i = 0; i < idx.len; i++)
    tls_decref(idx.tls[i]);

  free(idx.tls);
  idx.tls = NULL;
  idx.len = 0;

  pthread_rwlock_destroy(&idx.rwl);
}
