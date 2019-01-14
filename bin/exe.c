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

#include "exe.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <poll.h>

struct exe {
  pid_t pid;
  int fd;
};

exe_t *
exe_run(const char *cmd, bool shell, int socktype)
{
  int sv[2] = { -1, -1 };
  exe_t *exe = NULL;

  exe = malloc(sizeof(exe_t));
  if (!exe)
    return NULL;

  if (socketpair(AF_UNIX, socktype | SOCK_CLOEXEC, 0, sv) != 0) {
    free(exe);
    return NULL;
  }

  exe->pid = fork();
  if (exe->pid < 0) {
    close(sv[0]);
    close(sv[1]);
    free(exe);
    return NULL;
  }

  if (exe->pid == 0) {
    const char *args[4] = { cmd };

    if (shell) {
      args[0] = "/bin/sh";
      args[1] = "-c";
      args[2] = cmd;
    }

    dup2(sv[1], STDIN_FILENO);
    dup2(sv[1], STDOUT_FILENO);
    execv(args[0], (char **) args);
    exit(EXIT_FAILURE);
  }

  exe->fd = sv[0];
  close(sv[1]);
  return exe;
}

int
exe_fd(const exe_t *exe)
{
  return exe->fd;
}

int
exe_shutdown(exe_t *exe)
{
  pid_t pid = exe->pid;
  int fd = exe->fd;
  int status = 0;

  free(exe);
  close(fd);

  for (size_t i = 0; i < 10; i++) {
    if (waitpid(pid, &status, WNOHANG) != -1)
      return status;

    usleep(50000);
  }

  kill(pid, SIGTERM);

  for (size_t i = 0; i < 10; i++) {
    if (waitpid(pid, &status, WNOHANG) != -1)
      return status;

    usleep(50000);
  }

  kill(pid, SIGKILL);
  waitpid(pid, &status, 0);
  return status;
}

void
exe_cleanup(exe_t **exe)
{
  if (!exe || !*exe)
    return;

  exe_shutdown(*exe);
}
