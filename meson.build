project('tlssock', 'c',
  meson_version: '>= 0.49.0',
  version: '0.1.0',
)

cc = meson.get_compiler('c')

add_project_arguments(
  '-I' + meson.current_source_dir(),
  '-I' + meson.current_build_dir(),
  '-std=gnu99',
  '-Wall',
  '-Wextra',
  '-Werror',
  '-Wstrict-aliasing',
  '-Wchar-subscripts',
  '-Wformat-security',
  '-Wmissing-declarations',
  '-Wmissing-prototypes',
  '-Wnested-externs',
  '-Wpointer-arith',
  '-Wshadow',
  '-Wsign-compare',
  '-Wstrict-prototypes',
  '-Wtype-limits',
  '-Wunused-function',
  '-Wno-missing-field-initializers',
  '-Wno-unused-parameter',
  '-Wno-unknown-pragmas',
  language: 'c'
)

# Work around the fact that clang is overly-zealous in detecting unused
# variables when the cleanup attribute is used.
if cc.get_id() == 'clang'
  add_project_arguments('-Wno-unused-variable', language: 'c')
endif

pkg = import('pkgconfig')
dl = cc.find_library('dl', required: false)

openssl = dependency('openssl', version: '>=1.1.0', required: false)
gnutls = dependency('gnutls', version: '>=3.6.0', required: false)
threads = dependency('threads')

variants = [ openssl, gnutls ]
assert(variants.length() > 0, 'At least one TLS library is required!')

install_headers('lib/tlssock.h')

rev = executable('rev', 'tests/rev.c')
run = executable('run', 'tests/run.c')

tests = []
gnusrv = find_program('gnutls-serv', required: false)
gnuclt = find_program('gnutls-cli', required: false)
sslcli = find_program('openssl', required: false)
socat = find_program('socat', required: false)
nc = find_program('nc', required: false)
cat = find_program('cat').path()
foreach i, a: { 'IPv4': '127.0.0.1', 'IPv6': '::1' }
  if nc.found()
    tests += [[i, 'TCP', 'clt', 'nc', false, [
      nc.path(), a, '%PORT%'
    ]]]
    tests += [[i, 'TCP', 'esrv', 'nc', false, [
      nc.path(), '-e', cat, '-l', a, '%PORT%'
    ]]]
    tests += [[i, 'TCP', 'rsrv', 'nc', false,[
      nc.path(), '-e', rev.full_path(), '-l', a, '%PORT%'
    ]]]
  endif

  if socat.found()
    tests += [[i, 'TCP', 'clt', 'socat', false, [
      socat.path(), 'stdio', 'tcp:localhost:%PORT%,pf=' + i
    ]]]
    tests += [[i, 'TCP', 'esrv', 'socat', false, [
      socat.path(), 'tcp-listen:%PORT%,pf=' + i, 'exec:' + cat
    ]]]
    tests += [[i, 'TCP', 'rsrv', 'socat', false, [
      socat.path(), 'tcp-listen:%PORT%,pf=' + i, 'exec:' + rev.full_path()
    ]]]
  endif

  if gnuclt.found()
    tests += [[i, 'PSK', 'clt', 'gnutls-cli', false, [
      gnuclt.path(), '-p', '%PORT%', '--priority', 'NORMAL:+ECDHE-PSK:+DHE-PSK:+PSK',
                     '--pskusername=foo', '--pskkey=7df28f5439b5a051cc138b6e12128264', a
    ]]]
  endif

  if gnusrv.found()
    tests += [[i, 'PSK', 'esrv', 'gnutls-serv', true, [
      gnusrv.path(), '-p', '%PORT%', '--echo',
        '--priority', 'NORMAL:+ECDHE-PSK:+DHE-PSK:+PSK',
        '--pskpasswd=' + meson.current_source_dir() + '/tests/psk.txt'
    ]]]
  endif

  if sslcli.found()
    tests += [[i, 'PSK', 'clt', 'openssl', true, [
      sslcli.path(), 's_client', '-connect', '[' + a + ']:%PORT%', '-quiet',
        '-psk_identity', 'foo', '-psk', '7df28f5439b5a051cc138b6e12128264'
    ]]]
    tests += [[i, 'PSK', 'rsrv', 'openssl', true, [
      sslcli.path(), 's_server', '-nocert', '-rev', '-psk_identity', 'foo',
        '-accept', '[' + a + ']:%PORT%', '-psk', '7df28f5439b5a051cc138b6e12128264'
    ]]]
  endif
endforeach

foreach v: variants
  if not v.found()
    continue
  endif

  lib = shared_library('tlssock-' + v.name(), [
      'lib/tlssock.c', 'lib/tlssock.h',
      'lib/core.c', 'lib/core.h',
      'lib/idx.c', 'lib/idx.h',
      'lib/tls.h', 'lib/tls-' + v.name() + '.c',
    ],
    dependencies: [v, threads, dl],
    install: true,
  )

  pkg.generate(
    description: 'A library for doing TLS at the socket layer using ' + v.name(),
      libraries: lib,
           name: 'tlssock-' + v.name(),
        version: meson.project_version(),
    install_dir: join_paths(get_option('libdir'), 'pkgconfig')
  )

  tlssock = executable('tlssock-' + v.name(), [
      'bin/hex.c', 'bin/hex.h',
      'bin/non.c', 'bin/non.h',
      'bin/exe.c', 'bin/exe.h',
      'bin/opt.c', 'bin/opt.h',
      'bin/main.c',
    ],
    link_with: lib
  )

  foreach i, a: { 'IPv4': '127.0.0.1', 'IPv6': '::1' }
    tests += [[i, 'TCP', 'clt', 'ts-' + v.name(), false, [
      tlssock, a, '%PORT%'
    ]]]
    tests += [[i, 'TCP', 'esrv', 'ts-' + v.name(), false, [
      tlssock, '-e', cat, '-l', a, '%PORT%'
    ]]]
    tests += [[i, 'TCP', 'rsrv', 'ts-' + v.name(), false, [
      tlssock, '-e', rev.full_path(), '-l', a, '%PORT%'
    ]]]

    tests += [[i, 'PSK', 'clt', 'ts-' + v.name(), false, [
      tlssock, '-T', '-U', 'foo', '-K', '7df28f5439b5a051cc138b6e12128264',
               a, '%PORT%'
    ]]]
    tests += [[i, 'PSK', 'esrv', 'ts-' + v.name(), false, [
      tlssock, '-T', '-U', 'foo', '-K', '7df28f5439b5a051cc138b6e12128264',
               '-e', cat, '-l', a, '%PORT%'
    ]]]
    tests += [[i, 'PSK', 'rsrv', 'ts-' + v.name(), false, [
      tlssock, '-T', '-U', 'foo', '-K', '7df28f5439b5a051cc138b6e12128264',
               '-e', rev.full_path(), '-l', a, '%PORT%'
    ]]]
  endforeach
endforeach

foreach i: ['4', '6']
  foreach p: ['TCP', 'PSK']
    foreach c: tests
      if c[0] == 'IPv' + i and c[1] == p and c[2] == 'clt'
        foreach s: tests
          if s[0] == 'IPv' + i and s[1] == p and (s[2] == 'esrv' or s[2] == 'rsrv')
            args = ['--', c[5], '--', s[5]]

            if s[2] == 'rsrv'
              args = ['-r'] + args
            endif

            if c[4]
              args = ['-C'] + args
            endif

            if s[4]
              args = ['-S'] + args
            endif

            sep = s[2] == 'rsrv' ? ' => ' : ' -> '

            test(i + p + ': ' + c[3] + sep + s[3], run, args: args)
          endif
        endforeach
      endif
    endforeach
  endforeach
endforeach
