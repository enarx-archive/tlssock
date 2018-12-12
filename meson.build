project('tlssock', 'c',
  meson_version: '>= 0.40.0',
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

cc = meson.get_compiler('c')
dl = cc.find_library('dl', required: false)

gnutls = dependency('gnutls', version: '>=3.0.0')
threads = dependency('threads')

install_headers('src/tlssock.h')
libtlssock = shared_library('tlssock',
  'src/core.c', 'src/core.h',
  'src/tls.c', 'src/tls.h',
  'src/idx.c', 'src/idx.h',
  'src/tlssock.c', 'src/tlssock.h',
  dependencies: [gnutls, threads, dl],
  install: true,
)

pkg = import('pkgconfig')
pkg.generate(
  description: 'A library for doing TLS at the socket layer',
    libraries: libtlssock,
         name: 'tlssock',
      version: meson.project_version(),
  install_dir: join_paths(get_option('libdir'), 'pkgconfig')
)

echo = executable('echo', 'tests/echo.c', link_with: libtlssock)
test('PSK IPv4 TCP', echo, args: ['-p', 'foo:0123456789abcdef', '127.0.0.1'])
test('PSK IPv6 TCP', echo, args: ['-p', 'foo:0123456789abcdef', '::1'])
#test('PSK IPv4 UDP', server, args: ['-d', '-p', 'foo:0123456789abcdef', '127.0.0.1'])
#test('PSK IPv6 UDP', server, args: ['-d', '-p', 'foo:0123456789abcdef', '::1'])
