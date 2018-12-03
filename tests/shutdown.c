#include <sys/types.h>
#include <sys/socket.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>

static void
test_errno(int expected)
{
  if (errno != expected) {
    fprintf(stderr, "expected: %d: %s\n", expected, strerror(expected));
    fprintf(stderr, "received: %d: %m\n", errno);
    _exit(1);
  }
}

static void
test(int domain, int type)
{
  int fd;

  fd = socket(domain, type, 0);
  assert(fd >= 0);

  assert(shutdown(fd, SHUT_RDWR) == -1);
  test_errno(ENOTCONN);
}

int
main(int argc, const char *argv[])
{
  assert(shutdown(-1, SHUT_RDWR) == -1);
  test_errno(EBADF);

  assert(shutdown(1011, SHUT_RDWR) == -1);
  test_errno(EBADF);

  test(AF_INET, SOCK_STREAM);
  test(AF_INET, SOCK_DGRAM);
  test(AF_INET6, SOCK_STREAM);
  test(AF_INET6, SOCK_DGRAM);
}
