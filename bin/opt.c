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

#include "opt.h"
#include "hex.h"

#include <getopt.h>
#include <stdio.h>
#include <string.h>

static const char *sopts = "46hlknubTc:e:U:K:";
static const struct option lopts[] = {
  { "ipv4", no_argument, .val = '4' },
  { "ipv6", no_argument, .val = '6' },
  { "help", no_argument, .val = 'h' },
  { "listen", no_argument, .val = 'l' },
  { "udp", no_argument, .val = 'u' },
  { "block", no_argument, .val = 'b' },
  { "tls", no_argument, .val = 'T' },
  { "sh-exec", required_argument, .val = 'c' },
  { "exec", required_argument, .val = 'e' },

  { "psk-user", required_argument, .val = 'U' },
  { "psk-key", required_argument, .val = 'K' },
  {}
};

static const struct {
  int val;
  const char *doc;
  const char *arg;
} docs[] = {
  {'4', "Use IPv4 only"},
  {'6', "Use IPv6 only"},
  {'c', "Execute the given shell command", "CMD"},
  {'e', "Execute the given command", "CMD"},
  {'l', "Bind and listen for an incoming connection"},
  {'h', "Display this help message"},
  {'u', "Use UDP (or DTLS) instead of default (TCP [TLS])"},
  {'b', "User blocking sockets (internally)"},
  {'T', "Use TLS or DTLS instead of TCP or UDP"},
  {'U', "Pre-Shared Key authentication username", "NAME"},
  {'K', "Pre-Shared Key authentication key (hex)", "HEX"},
  {}
};

bool
opts_parse(options_t *opts, int argc, char **argv)
{
  if (!argv || !*argv)
    goto usage;

  memset(opts, 0, sizeof(*opts));
  opts->host = "localhost";
  opts->port = "31337";

  for (int c; (c = getopt_long(argc, argv, sopts, lopts, NULL)) >= 0; ) {
    switch (c) {
    case 'h': goto usage;

    case '4': opts->ipv4 = true; break;
    case '6': opts->ipv6 = true; break;
    case 'l': opts->listen = true; break;
    case 'u': opts->udp = true; break;
    case 'b': opts->block = true; break;
    case 'T': opts->tls = true; break;
    case 'c': opts->exec = optarg; opts->shell = true; break;
    case 'e': opts->exec = optarg; opts->shell = false; break;
    case 'U': opts->psku = optarg; break;

    case 'K':
      opts->pskk = optarg;
      if (hex2bin(opts->pskk, NULL, strlen(opts->pskk) / 2))
        break;

      fprintf(stderr, "The -K option contains invalid hex!\n\n");
      goto usage;

    default:
      fprintf(stderr, "Unknown option: %c!\n\n", c);
      goto usage;
    }
  }

  if (optind < argc)
    opts->host = argv[optind++];

  if (optind < argc)
    opts->port = argv[optind++];

  if (opts->ipv4 && opts->ipv6) {
    fprintf(stderr, "Can only specify one of -4 or -6!\n\n");
    goto usage;
  }

  if (opts->psku && !opts->tls) {
    fprintf(stderr, "The -U option requires the -T option!\n\n");
    goto usage;
  }

  if (opts->pskk && !opts->tls) {
    fprintf(stderr, "The -K option requires the -T option!\n\n");
    goto usage;
  }

  return true;

usage:
  fprintf(stderr, "tlssock [options] [hostname] [port]\n");
  fprintf(stderr, "\n");

  for (size_t i = 0; lopts[i].name; i++) {
    for (size_t j = 0; docs[j].doc; j++) {
      if (lopts[i].val != docs[j].val)
        continue;

      const size_t val = docs[j].arg ? strlen(docs[j].arg) : 0;
      const size_t key = strlen(lopts[i].name);
      char lterm[key + val + 4];
      char sterm[val + 4];

      if (!docs[j].arg || lopts[i].has_arg == no_argument) {
          sprintf(sterm, ",");
          sprintf(lterm, "%s%s", lopts[i].name, "");
      } else if (lopts[i].has_arg == required_argument) {
          sprintf(sterm, " %s,", docs[j].arg);
          sprintf(lterm, "%s=%s", lopts[i].name, docs[j].arg);
      } else {
          sprintf(sterm, " [%s],", docs[j].arg);
          sprintf(lterm, "%s[=%s]", lopts[i].name, docs[j].arg);
      }

      fprintf(stderr, "  -%c%-7s --%-18s %s\n",
              docs[j].val, sterm, lterm, docs[j].doc);
    }
  }
  return false;
}

