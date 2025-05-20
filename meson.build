project(
  'cydrogen',
  'c', 'cython',
  license: 'Apache-2.0',
  meson_version: '>= 1.8.0',
  version: run_command(['tools/gitversion.py'], check: true).stdout().strip(),
  default_options: [
    'buildtype=release',
  ]
)

cc = meson.get_compiler('c')
py = import('python').find_installation(pure: false)
py_dep = py.dependency()
fs = import('fs')

# Hide symbols when building on Linux with GCC. For Python extension modules,
# we only need `PyInit_*` to be public, anything else may cause problems. So we
# use a linker script to avoid exporting those symbols (this is in addition to
# Meson using `-fvisibility=hidden` for C and `-fvisibility-inlines-hidden` for
# C++ code.
_linker_script = meson.project_source_root() / 'tools/link-version-pyinit.map'
version_link_args = ['-Wl,--version-script=' + _linker_script]
# Note that FreeBSD only accepts version scripts when -shared is passed,
# hence we need to pass that to `cc.links` explicitly (flag is already
# present for `extension_module` invocations).
if not cc.links('', name: '-Wl,--version-script', args: ['-shared', version_link_args])
  version_link_args = []
endif

subdir('cydrogen')
