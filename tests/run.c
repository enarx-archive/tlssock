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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>

#define pid_auto_t pid_t __attribute__((cleanup(pid_cleanup)))
#define fd_auto_t fd_t __attribute__((cleanup(fd_cleanup)))

typedef int fd_t;

static void
pid_cleanup(pid_t *pid)
{
  if (!pid || *pid < 0)
    return;

  if (waitpid(*pid, NULL, WNOHANG) != *pid) {
    kill(*pid, SIGTERM);
    waitpid(*pid, NULL, 0);
  }

  *pid = -1;
}

static void
fd_cleanup(fd_t *fd)
{
  if (!fd || *fd < 0)
    return;

  close(*fd);
  *fd = -1;
}

static fd_t
fd_steal(fd_t *fd)
{
  fd_t f = -1;

  if (fd) {
    f = *fd;
    *fd = -1;
  }

  return f;
}

static int
pair(int flags, fd_t *rd, fd_t *wr)
{
  int fd[2] = { -1, -1 };
  int ret;

  ret = pipe2(fd, flags);
  if (ret != 0)
    return ret;

  *wr = fd[1];
  *rd = fd[0];
  return 0;
}

static pid_t
spawn(char *args[], fd_t *rd, fd_t *wr)
{
  fd_auto_t cout = -1;
  fd_auto_t pout = -1;
  fd_auto_t oout = -1;
  fd_auto_t cin = -1;
  fd_auto_t pin = -1;
  fd_auto_t oin = -1;
  int status;
  pid_t pid;
  char c;

  if (rd) {
    if (pair(O_CLOEXEC, &pin, &cout) != 0)
      return -1;
  }

  if (wr) {
    if (pair(O_CLOEXEC, &cin, &pout) != 0)
      return -1;
  }

  if (pair(O_CLOEXEC | O_DIRECT, &oin, &oout) != 0)
    return -1;

  pid = fork();
  if (pid < 0)
    return pid;

  if (pid == 0) {
    dup2(cin, STDIN_FILENO);
    dup2(cout, STDOUT_FILENO);
    execvp(args[0], args);
    exit(EXIT_FAILURE);
  }

  fd_cleanup(&oout);
  read(oin, &c, 1);
  if (waitpid(pid, &status, WNOHANG) == pid)
    return -1;

  if (rd)
    *rd = fd_steal(&pin);

  if (wr)
    *wr = fd_steal(&pout);

  return pid;
}

static char *
replace(char *str, const char *old, const char *new)
{
  size_t nlen;
  size_t olen;

  olen = strlen(old);
  nlen = strlen(new);
  if (olen < nlen)
    abort();

  for (char *s = strstr(str, old); s; s = strstr(s + nlen, old)) {
    memmove(s + nlen, s + olen, strlen(s + olen) + 1);
    strncpy(s, new, nlen);
  }

  return str;
}

static char *
substitute(char *str, uint16_t port)
{
  char new[] = "65535";
  snprintf(new, sizeof(new), "%hu", port);
  replace(str, "%PORT%", new);
  return str;
}

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
  char msg[] = "abcdefgh\n";
  struct timespec tms;
  char buf[1024];
  uint16_t port;

  char *cargs[argc];
  char *sargs[argc];
  char **args = cargs;

  pid_auto_t cpid = -1;
  pid_auto_t spid = -1;
  fd_auto_t out = -1;
  fd_auto_t in = -1;
  int cstatus;
  int sstatus;
  ssize_t ret;

  bool ckill = false;
  bool skill = false;
  bool rev = false;

  clock_gettime(CLOCK_REALTIME, &tms);
  srand(getpid() + tms.tv_nsec);
  port = 1024 + rand() % 64511;

  memset(buf, 0, sizeof(buf));
  memset(cargs, 0, sizeof(cargs));
  memset(sargs, 0, sizeof(sargs));

  for (int c; (c = getopt(argc, argv, "rCS")) >= 0; ) {
    switch (c) {
    case 'r':
      rev = true;
      break;

    case 'C':
      ckill = true;
      break;

    case 'S':
      skill = true;
      break;

    default:
      fprintf(stderr, "Unknown option: %c!\n", c);
      fprintf(stderr, "Usage: %s [-r] [-C] [-S]\n\n", argv[0]);
      fprintf(stderr, "-r: Server behaves like rev\n");
      fprintf(stderr, "-C: Kill client when test complete\n");
      fprintf(stderr, "-S: Kill server when test complete\n");
      return EXIT_FAILURE;
    }
  }

  for (int i = optind, j = 0; i < argc; i++) {
    switch (strcmp(argv[i], "--")) {
    case 0: args = sargs; j = 0; break;
    default: args[j++] = substitute(argv[i], port); break;
    }
  }

  fprintf(stderr, "client: ");
  for (int i = 0; cargs[i]; i++)
    fprintf(stderr, "%s%s", cargs[i], cargs[i + 1] ? " " : "\n");

  fprintf(stderr, "server: ");
  for (int i = 0; sargs[i]; i++)
    fprintf(stderr, "%s%s", sargs[i], sargs[i + 1] ? " " : "\n");

  if (cargs[0] == NULL || sargs[0] == NULL) {
    fprintf(stderr, "Invalid arguments!\n");
    return EXIT_FAILURE;
  }

  spid = spawn(sargs, NULL, NULL);
  if (spid < 0) {
    fprintf(stderr, "Failure spawining server!\n");
    return EXIT_FAILURE;
  }

  usleep(100000);

  cpid = spawn(cargs, &in, &out);
  if (cpid < 0) {
    fprintf(stderr, "Failure spawining client!\n");
    return EXIT_FAILURE;
  }

  ret = write(out, msg, strlen(msg));
  fprintf(stderr, "wrote: %zd: %s\n", ret, msg);
  if (ret != (ssize_t) strlen(msg))
    return EXIT_FAILURE;

  ret = read(in, buf, sizeof(buf) - 1);
  fprintf(stderr, "read: %zd: %s\n", ret, buf);
  if (ret != (ssize_t) strlen(msg))
    return EXIT_FAILURE;

  fd_cleanup(&out);
  fd_cleanup(&in);

  if (rev)
    reverse(buf, ret);

  if (strcmp(msg, buf) != 0)
    return EXIT_FAILURE;

  if (ckill) {
    fprintf(stderr, "Killing client...\n");
    kill(cpid, SIGTERM);
  }

  if (skill) {
    fprintf(stderr, "Killing server...\n");
    kill(spid, SIGTERM);
  }

  fprintf(stderr, "Waiting for client...\n");
  if (waitpid(cpid, &cstatus, 0) != cpid)
    return EXIT_FAILURE;
  cpid = -1;
  if (ckill)
    cstatus = 0;

  fprintf(stderr, "Waiting for server...\n");
  if (waitpid(spid, &sstatus, 0) != spid)
    return EXIT_FAILURE;
  spid = -1;
  if (skill)
    sstatus = 0;

  fprintf(stderr, "cstatus: %d\n", cstatus);
  fprintf(stderr, "sstatus: %d\n", sstatus);
  return WEXITSTATUS(sstatus) | WEXITSTATUS(sstatus);
}
