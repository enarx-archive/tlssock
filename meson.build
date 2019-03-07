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
  '-D_GNU_SOURCE',
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
ncat = find_program('ncat', required: false)
cat = find_program('cat').path()

psk = '7df28f5439b5a051cc138b6e12128264'
foreach n: ['4', '6']
  h = 'localhost' + n

  r = run_command('grep', h, '/etc/hosts')
  if r.returncode() != 0
    error('Failed to find localhost4/localhost6 in /etc/hosts!')
  endif

  if ncat.found()
    tests += [[n, 'TCP', 'clt', 'ncat', false, [
      ncat.path(), h, '%PORT%'
    ]]]
    tests += [[n, 'TCP', 'esrv', 'ncat', false, [
      ncat.path(), '-e', cat, '-l', h, '%PORT%'
    ]]]
    tests += [[n, 'TCP', 'rsrv', 'ncat', false,[
      ncat.path(), '-e', rev.full_path(), '-l', h, '%PORT%'
    ]]]
  endif

  if socat.found()
    tests += [[n, 'TCP', 'clt', 'socat', false, [
      socat.path(), 'stdio', 'tcp:' + h + ':%PORT%'
    ]]]
    tests += [[n, 'TCP', 'esrv', 'socat', false, [
      socat.path(), 'tcp-listen:%PORT%,pf=ipv' + n, 'exec:' + cat
    ]]]
    tests += [[n, 'TCP', 'rsrv', 'socat', false, [
      socat.path(), 'tcp-listen:%PORT%,pf=ipv' + n, 'exec:' + rev.full_path()
    ]]]
  endif

  if gnuclt.found() and false
    tests += [[n, 'PSK', 'clt', 'gnutls-cli', false, [
      gnuclt.path(), '-p', '%PORT%', '--pskusername=foo', '--pskkey=' + psk,
                     '--priority', 'NORMAL:+ECDHE-PSK:+DHE-PSK:+PSK', h
    ]]]
  endif

  if gnusrv.found()
    tests += [[n, 'PSK', 'esrv', 'gnutls-serv', true, [
      gnusrv.path(), '-p', '%PORT%', '--echo',
        '--priority', 'NORMAL:+ECDHE-PSK:+DHE-PSK:+PSK',
        '--pskpasswd=' + meson.current_source_dir() + '/tests/psk.txt'
    ]]]
  endif

  if sslcli.found()
    tests += [[n, 'PSK', 'clt', 'openssl', true, [
      sslcli.path(), 's_client', '-connect', h + ':%PORT%', '-quiet',
        '-psk_identity', 'foo', '-psk', psk
    ]]]
    tests += [[n, 'PSK', 'rsrv', 'openssl', true, [
      sslcli.path(), 's_server', '-nocert', '-rev', '-psk_identity', 'foo',
        '-accept', h + ':%PORT%', '-psk', psk
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
      'lib/locks.c', 'lib/locks.h',
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

  foreach n: ['4', '6']
    h = 'localhost' + n

    tests += [[n, 'TCP', 'clt', 'ts-' + v.name(), false, [
      tlssock, h, '%PORT%'
    ]]]
    tests += [[n, 'TCP', 'esrv', 'ts-' + v.name(), false, [
      tlssock, '-e', cat, '-l', h, '%PORT%'
    ]]]
    tests += [[n, 'TCP', 'rsrv', 'ts-' + v.name(), false, [
      tlssock, '-e', rev.full_path(), '-l', h, '%PORT%'
    ]]]

    tests += [[n, 'PSK', 'clt', 'ts-' + v.name(), false, [
      tlssock, '-T', '-U', 'foo', '-K', psk, h, '%PORT%'
    ]]]
    tests += [[n, 'PSK', 'esrv', 'ts-' + v.name(), false, [
      tlssock, '-lT', '-U', 'foo', '-K', psk, '-e', cat, h, '%PORT%'
    ]]]
    tests += [[n, 'PSK', 'rsrv', 'ts-' + v.name(), false, [
      tlssock, '-lT', '-U', 'foo', '-K', psk, '-e', rev.full_path(), h, '%PORT%'
    ]]]
  endforeach
endforeach

# A single test consists of three elements of the tests array: a 'clt', an
# 'esrv', and an 'rsrv'.  The tests array is, in order:
#
# - IP protocol ('4' or '6')
# - strategy ('TCP' or 'PSK') - used for differentiation
# - behavior ('clt' (client), 'esrv' (echo), or 'rsrv' (rev))
# - name, used only for logging the (a->b) stuff
# - whether to kill the particular job on completion
# - an array containing argv for the executable (including the meson obj)
#
# So what this does: for every "clt" test, it looks for corresponding 'esrv'
# and 'rsrv' tests.  I can read it now, but I can't fix it.
foreach ip: ['4', '6']
  foreach strat: ['TCP', 'PSK']
    foreach client: tests
      if client[0] == ip and client[1] == strat and client[2] == 'clt'
        foreach server: tests
          if server[0] == ip and server[1] == strat and (server[2] == 'esrv' or server[2] == 'rsrv')
            args = ['--', client[5], '--', server[5]]

            if server[2] == 'rsrv'
              args = ['-r'] + args
            endif

            if client[4]
              args = ['-C'] + args
            endif

            if server[4]
              args = ['-S'] + args
            endif

            sep = server[2] == 'rsrv' ? ' => ' : ' -> '

            test(ip + strat + ': ' + client[3] + sep + server[3], run, args: args)
          endif
        endforeach
      endif
    endforeach
  endforeach
endforeach
