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

#include <string.h>
#include <unistd.h>
#include <stdlib.h>

static void
reverse(char *str, size_t len)
{
  while (len > 0 && str[len - 1] == '\n')
    len--;

  if (len == 0)
    return;

  for (size_t f = 0, b = len - 1; f < b; f++, b--) {
    str[f] ^= str[b];
    str[b] ^= str[f];
    str[f] ^= str[b];
  }
}

int
main(int argc, char *argv[])
{
  while (1) {
    char buf[64 * 1024];
    ssize_t r;

    memset(buf, 0, sizeof(buf));

    r = read(STDIN_FILENO, buf, sizeof(buf) - 1);
    if (r == 0)
      return EXIT_SUCCESS;
    if (r < 0)
      return EXIT_FAILURE;

    reverse(buf, r);

    if (write(STDOUT_FILENO, buf, r) != r)
      return EXIT_FAILURE;
  }
}
