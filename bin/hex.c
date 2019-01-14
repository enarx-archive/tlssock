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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "hex.h"

#include <string.h>

static uint8_t
hex2low(uint8_t c)
{
  static uint8_t table[UINT8_MAX] = {
    ['0'] = 1, ['1'] = 2, ['2'] = 3, ['3'] = 4, ['4'] = 5,
    ['5'] = 6, ['6'] = 7, ['7'] = 8, ['8'] = 9, ['9'] = 10,
    ['A'] = 11, ['B'] = 12, ['C'] = 13, ['D'] = 14, ['E'] = 15, ['F'] = 16,
    ['a'] = 11, ['b'] = 12, ['c'] = 13, ['d'] = 14, ['e'] = 15, ['f'] = 16,
  };

  return table[c] - 1;
}

bool
hex2bin(const char *hex, uint8_t *bin, size_t len)
{
  if (strlen(hex) != len * 2)
    return false;

  for (size_t i = 0; i < len * 2; i += 2) {
    uint8_t h = hex2low(hex[i]);
    uint8_t l = hex2low(hex[i + 1]);

    if (h == UINT8_MAX || l == UINT8_MAX)
      return false;

    if (bin)
      bin[i / 2] = h << 4 | l;
  }

  return true;
}
