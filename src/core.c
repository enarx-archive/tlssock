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

#include "core.h"
#include "tlssock.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>

bool
is_tls_domain(int domain)
{
    return domain == AF_INET || domain == AF_INET6;
}

bool
is_tls_type(int type)
{
    return type == SOCK_STREAM || type == SOCK_DGRAM;
}

bool
is_tls_inner_protocol(int protocol)
{
    return protocol == 0 || protocol == IPPROTO_TCP || protocol == IPPROTO_UDP;
}

int
getsockopt_int(int fd, int level, int optname, int *optval)
{
  socklen_t len = sizeof(*optval);
  int ret;

  ret = NEXT(getsockopt)(fd, level, optname, optval, &len);

  if (ret == 0 && len != sizeof(*optval)) {
    errno = EINVAL; // FIXME
    return -1;
  }

  return ret;
}
