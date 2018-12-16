project('tlssock', 'c',
  meson_version: '>= 0.49.0',
  version: '0.1.0',
)

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
  '-Wno-unused-command-line-argument',
  '-Wno-unused-parameter',
  '-Wno-unknown-pragmas',
  language: 'c'
)

pkg = import('pkgconfig')
cc = meson.get_compiler('c')
dl = cc.find_library('dl', required: false)

openssl = dependency('openssl', version: '>=1.1.0', required: false)
gnutls = dependency('gnutls', version: '>=3.6.0', required: false)
threads = dependency('threads')

variants = [ openssl, gnutls ]
assert(variants.length() > 0, 'At least one TLS library is required!')

install_headers('src/tlssock.h')

core = [
  'src/tlssock.c',
  'src/tlssock.h',
  'src/core.c',
  'src/core.h',
  'src/idx.c',
  'src/idx.h',
  'src/tls.h',
]

foreach v : variants
  if not v.found()
    continue
  endif

  name = v.name()

  lib = shared_library('tlssock-' + name,
    core + ['src/tls-' + name + '.c'],
    dependencies: [v, threads, dl],
    install: true,
  )

  pkg.generate(
    description: 'A library for doing TLS at the socket layer using ' + name,
      libraries: lib,
           name: 'tlssock-' + name,
        version: meson.project_version(),
    install_dir: join_paths(get_option('libdir'), 'pkgconfig')
  )

  echo = executable('echo-' + name, 'tests/echo.c', link_with: lib)
  test(name + ': PSK IPv4 TCP', echo,
       args: ['-p', 'foo:0123456789abcdef', '127.0.0.1'])
  test(name + ': PSK IPv6 TCP', echo,
       args: ['-p', 'foo:0123456789abcdef', '::1'])
  #test(name + ': PSK IPv4 UDP', echo,
  #     args: ['-d', '-p', 'foo:0123456789abcdef', '127.0.0.1'])
  #test(name + ': PSK IPv6 UDP', echo,
  #     args: ['-d', '-p', 'foo:0123456789abcdef', '::1'])
endforeach
