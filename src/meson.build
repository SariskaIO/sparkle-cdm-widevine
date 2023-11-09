glib_dep = dependency('glib-2.0')
gmodule_dep = dependency('gmodule-2.0')
gio_dep = dependency('gio-2.0')
gst_dep = dependency('gstreamer-1.0')
gst_base_dep = dependency('gstreamer-base-1.0')

sparkle_cdm_widevine = library(
  'sparkle-cdm-widevine',
  'system.cpp',
  'session.cpp',
  'search.c',
  override_options: ['cpp_std=c++20'],
  dependencies: [
    glib_dep,
    gmodule_dep,
    gio_dep,
    gst_dep,
    gst_base_dep,
  ],
  install: true,
  install_dir: get_option('prefix') / get_option('libdir'),
)

sparkle_cdm_widevine_dep = declare_dependency(link_with: sparkle_cdm_widevine)

devenv = environment(
  {'WEBKIT_SPARKLE_CDM_MODULE_PATH': sparkle_cdm_widevine.full_path()},
  method: 'append',
)
meson.add_devenv(devenv)

search_test = executable(
  'search-test',
  'search.c',
  'search-test.c',
  dependencies: [glib_dep, gio_dep],
  install: false,
)
test('search-test', search_test, env: ['G_DEBUG=fatal-warnings'])
