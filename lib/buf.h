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
#include <stdint.h>
#include <sys/types.h>

/*
 * This is exposed so it's size is known and certain fields can be read (peek,
 * but without allocation).  I don't recommend writing to it, but if you do,
 * here are the invariants three:
 *
 *  1. if data != NULL, data was allocated
 *  2. capacity => length => offset
 *  3. if offset == length, the buffer will be "reset" (db_reset)
 *
 * Note that these aren't NULL-terminated, so don't do that.  I'd
 * NULL-terminate them, but that'd just encourage bad habits.
 *
 * A dyn_buf is a dynamic ring buffer.  Data is "pushed" starting at
 * data+length, and "popped" starting at data->offset.
 */

typedef struct dyn_buf {
  uint8_t *data;
  size_t offset; /* for reading */
  size_t length; /* for writing */
  size_t capacity;
} dyn_buf;

/*
 * It's valid to initialize set to 0, or it can be initialized with a set
 * starting capacity.  The buffer will never shrink, even when reset, so we
 * don't bother doing anything fancy with growth (the allocator can if it
 * cares).
 */
int db_init_sized(dyn_buf *db, size_t capacity);
void db_free(dyn_buf *db);

/* Dump all data stored. */
void db_reset(dyn_buf *db);

/* Check number of bytes in queue. */
size_t db_len_avail(dyn_buf *db);

/* Enqueue. */
int db_add_bytes(dyn_buf *db, uint8_t *bytes, size_t bytes_len);
int db_make_available(dyn_buf *db, int fd, size_t total);

/* Dequeue. */
ssize_t db_sink_fd(dyn_buf *db, int fd);
size_t db_sink_buf(dyn_buf *db, void *buf, size_t max);

/* Peek. */
uint8_t *db_head(dyn_buf *db);
