gdhcp_header_subdir = join_paths(package_subdir, 'gdhcp-' + apiversion)
gdhcp_header_dir = join_paths(get_option('includedir'), gdhcp_header_subdir)

version_data = configuration_data()
version_data.set('MAJOR_VERSION', jsonrpc_glib_version_major)
version_data.set('MINOR_VERSION', jsonrpc_glib_version_minor)
version_data.set('MICRO_VERSION', jsonrpc_glib_version_micro)
version_data.set('VERSION', meson.project_version())

jsonrpc_version_h = configure_file(
          input: 'jsonrpc-version.h.in',
         output: 'jsonrpc-version.h',
    install_dir: gdhcp_header_dir,
        install: true,
  configuration: version_data)

gdhcp_generated_headers = [
  jsonrpc_version_h,
]

gdhcp_public_headers = [
  'jsonrpc-client.h',
  'jsonrpc-glib.h',
  'jsonrpc-input-stream-private.h',
  'jsonrpc-input-stream.h',
  'jsonrpc-message.h',
  'jsonrpc-output-stream.h',
  'jsonrpc-server.h',
  'jsonrpc-version-macros.h',
]

gdhcp_public_sources = [
  'jsonrpc-client.c',
  'jsonrpc-input-stream.c',
  'jsonrpc-message.c',
  'jsonrpc-output-stream.c',
  'jsonrpc-server.c',
]

gdhcp_deps = [
  dependency('gio-2.0'),
  dependency('json-glib-1.0'),
]

gdhcp_sources = [
  gdhcp_generated_headers,
  gdhcp_public_headers,
  gdhcp_public_sources,
]

gdhcp = library(
  'jsonrpc-glib-' + apiversion,
  gdhcp_sources,

        c_args: hidden_visibility_args,
  dependencies: gdhcp_deps,
     soversion: soversion,
       version: libversion,
       install: true,
)

gdhcp_dep = declare_dependency(
              sources: gdhcp_generated_headers,
         dependencies: gdhcp_deps,
            link_with: gdhcp,
  include_directories: include_directories('.'),
)

if get_option('with_introspection')

  gdhcp_gir = gnome.generate_gir(gdhcp,
                sources: gdhcp_generated_headers + gdhcp_public_headers + gdhcp_public_sources,
              nsversion: apiversion,
              namespace: 'Jsonrpc',
          symbol_prefix: 'jsonrpc',
      identifier_prefix: 'Jsonrpc',
              link_with: gdhcp,
               includes: [ 'Gio-2.0', 'Json-1.0' ],
                install: true,
        install_dir_gir: girdir,
    install_dir_typelib: typelibdir,
             extra_args: [ '--c-include=jsonrpc-glib.h' ],
  )

  if get_option('with_vapi')

    gdhcp_vapi = gnome.generate_vapi('jsonrpc-glib-' + apiversion,
          sources: gdhcp_gir[0],
         packages: [ 'gio-2.0', 'json-glib-1.0' ],
          install: true,
      install_dir: vapidir,
    )

  endif
endif

install_headers(gdhcp_public_headers, subdir: gdhcp_header_subdir)

pkgg = import('pkgconfig')

pkgg.generate(
    libraries: [gdhcp],
      subdirs: gdhcp_header_subdir,
      version: meson.project_version(),
         name: 'Jsonrpc-GLib',
     filebase: 'jsonrpc-glib-@0@'.format(apiversion),
  description: 'A jsonrpc library for GLib',
     requires: [ 'gio-2.0', 'json-glib-1.0' ],
  install_dir: join_paths(libdir, 'pkgconfig'),
)

