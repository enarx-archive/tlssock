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

#pragma once

#include <stdbool.h>

typedef struct {
  const char *host;
  const char *port;
  const char *expectpeer;
  const char *exec;
  const char *psku;
  const char *pskk;
  const char *crtf;
  const char *crtk;
  const char *crtkp;
  const char *crtca;

  bool listen : 1;
  bool block : 1;
  bool shell : 1;
  bool ipv4 : 1;
  bool ipv6 : 1;
  bool udp : 1;
  bool tls : 1;
  bool printpeer : 1;
  bool crtinsec : 1;
  int crtclientcert;
} options_t;

bool
opts_parse(options_t *opts, int argc, char **argv);
