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

#include "buf.h"
#include "core.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
db_init_sized(dyn_buf *db, size_t capacity)
{
  memset(db, 0, sizeof(*db));
  db->data = malloc(capacity);
  if (!db->data)
    return -1;
  db->capacity = capacity;
  return 0;
}

static int
db_ensure_space(dyn_buf *db, size_t bytes_len)
{
  uint8_t *new_data;
  size_t new_capacity;

  if (db->capacity - db->length >= bytes_len)
    return 0;

  new_capacity = db->capacity - db->length + bytes_len;
  if (new_capacity < db->capacity) {
    errno = ENOMEM;
    return -1;
  }

  new_data = realloc(db->data, new_capacity);
  if (!new_data)
    return -1;

  db->data = new_data;
  db->capacity = new_capacity;
  return 0;
}

int
db_add_bytes(dyn_buf *db, uint8_t *bytes, size_t bytes_len)
{
  int ret;

  ret = db_ensure_space(db, bytes_len);
  if (ret < 0)
    return ret;

  memcpy(db->data + db->length, bytes, bytes_len);
  db->length += bytes_len;
  return 0;
}

/* 1 for number are available, 0 for 0-length read, otherwise return
 * code/errno from underlying socket call. */
int
db_make_available(dyn_buf *db, int fd, size_t total)
{
  int ret;
  size_t curcap;

  curcap = db_len_avail(db);
  if (curcap >= total)
    return 1;

  ret = db_ensure_space(db, total - curcap);
  if (ret < 0)
    return ret;

  ret = NEXT(read)(fd, db->data + db->length, total - curcap);
  if (ret <= 0)
    return ret;
  db->length += ret;

  if (db_len_avail(db) >= total)
    return total;
  errno = EWOULDBLOCK;
  return -1;
}

void
db_reset(dyn_buf *db)
{
  if (db->data)
    explicit_bzero(db->data, db->length);
  db->offset = db->length = 0;
}

void
db_free(dyn_buf *db)
{
  db_reset(db);
  free(db->data);
  db->data = NULL;
}

size_t
db_len_avail(dyn_buf *db)
{
  if (!db->data)
    return 0;
  return db->length - db->offset;
}

ssize_t
db_sink_fd(dyn_buf *db, int fd)
{
  ssize_t ret;

  if (!db_len_avail(db))
    return 0;

  ret = NEXT(write)(fd, db->data + db->offset, db->length - db->offset);
  if (ret < 0)
    return ret;

  db->offset += ret;
  if (db->offset == db->length)
    db_reset(db);
  return ret;
}

size_t
db_sink_buf(dyn_buf *db, void *buf, size_t max)
{
  if (max > db_len_avail(db))
    max = db_len_avail(db);

  memcpy(buf, db->data + db->offset, max);
  db->offset += max;
  if (db->offset == db->length)
    db_reset(db);
  return max;
}

inline uint8_t *
db_head(dyn_buf *db)
{
  return db->data + db->offset;
}
