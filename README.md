[![Build Status](https://travis-ci.org/enarx/tlssock.svg?branch=master)](https://travis-ci.org/enarx/tlssock)
[![Code Coverage](https://codecov.io/gh/enarx/tlssock/branch/master/graph/badge.svg)](https://codecov.io/gh/enarx/tlssock)

# TLSSock

Welcome to TLSSock!

TLSSock is a library which wraps the POSIX networking APIs
in order to provide TLS and DTLS connecivity without invasive application
restructuring. For example, you can write your application using normal TCP/IP
sockets and then, with a few #ifdefs, convert your application to use TLS.

This is accomplished by creating a new `PROT_TLS` protocol for the `socket()`
system call. Any sockets created with this protocol will be encrypted using TLS.

TLS requires additional configuration. This is accomplished by adding new
protocol-level socket options for the `PROT_TLS` protocol. These options can
be set using `setsockopt()`.

# Workflow

This directed graph demonstrats the order of calls in order to get a working
TLS connection on either the server-side or the client-side. Grey function calls
are optional and will depend on your application's needs.

![Workflow](https://g.gravizo.com/source/svg?https%3A%2F%2Fraw.githubusercontent.com%2Fenarx%2Ftlssock%2Fmaster%2Fworkflow.dot)
```mermaid
graph TD;
  A-->B;
  A-->C;
  B-->D;
  C-->D;
 ```
