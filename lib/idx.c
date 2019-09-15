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

#include "idx.h"

#include <pthread.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

static long pagesize;

bool
idx_set(idx_t *idx, int fd, void *elt, void *already_in)
{
  void **already = already_in;

  if (fd < 0)
    return false;

  pthread_rwlock_wrlock(&idx->rwl);

  if (idx->len <= (unsigned int) fd) {
    const int block = pagesize / sizeof(void*);
    void **tmp = NULL;
    size_t len = 0;

    len = (fd + block) / block * block;
    tmp = realloc(idx->elts, sizeof(void*) * len);
    if (!tmp)
      goto error;

    memset(&tmp[idx->len], 0, sizeof(void*) * (len - idx->len));
    idx->len = len;
    idx->elts = tmp;
  }

  if (idx->elts[fd]) {
    if (already) {
      *already = idx->incref(idx->elts[fd]);
      if (*already)
        goto error;
    }

    errno = EALREADY;
    goto error;
  }

  idx->elts[fd] = idx->incref(elt);
  if (!idx->elts[fd])
    goto error;

  pthread_rwlock_unlock(&idx->rwl);
  return true;

error:
  pthread_rwlock_unlock(&idx->rwl);
  return false;
}

void *
idx_get(idx_t *idx, int fd)
{
  void *elt = NULL;

  if (fd < 0)
    return NULL;

  pthread_rwlock_rdlock(&idx->rwl);

  if (idx->len <= (unsigned int) fd)
    goto error;

  elt = idx->incref(idx->elts[fd]);

error:
  pthread_rwlock_unlock(&idx->rwl);
  return idx->incref(elt);
}

bool
idx_del(idx_t *idx, int fd)
{
  bool found = false;

  if (fd < 0) {
    errno = EBADF; // FIXME
    return false;
  }

  pthread_rwlock_wrlock(&idx->rwl);

  if (idx->len > (unsigned int) fd && idx->elts[fd]) {
    idx->decref(idx->elts[fd]);
    idx->elts[fd] = NULL;
    found = true;
  }

  pthread_rwlock_unlock(&idx->rwl);

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

void
idx_destroy(idx_t *idx)
{
  pthread_rwlock_wrlock(&idx->rwl);

  for (size_t i = 0; i < idx->len; i++)
    idx->decref(idx->elts[i]);

  free(idx->elts);
  idx->elts = NULL;
  idx->len = 0;

  pthread_rwlock_destroy(&idx->rwl);
}
