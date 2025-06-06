project(
  'cydrogen',
  'c', 'cython',
  license: 'Apache-2.0',
  meson_version: '>= 1.8.0',
  version: run_command(['tools/gitversion.py'], check: true).stdout().strip(),
)

cc = meson.get_compiler('c')

add_project_arguments('-DCYTHON_CLINE_IN_TRACEBACK=0', language: 'c')
add_project_arguments('-DCYTHON_CLINE_IN_TRACEBACK_RUNTIME=0', language: 'c')

if cc.check_header('sys/mman.h')
  add_project_arguments('-DHAVE_SYS_MMAN_H', language: 'c')
  if cc.has_function('mmap', prefix : '#include <sys/mman.h>')
    add_project_arguments('-DHAVE_MMAP', language: 'c')
  endif
  if cc.has_function('mprotect', prefix : '#include <sys/mman.h>')
    add_project_arguments('-DHAVE_MPROTECT', language: 'c')
  endif
  if cc.has_function('mlock', prefix : '#include <sys/mman.h>')
    add_project_arguments('-DHAVE_MLOCK', language: 'c')
  endif
  # madvise
  if cc.has_function('madvise', prefix : '#include <sys/mman.h>')
    add_project_arguments('-DHAVE_MADVISE', language: 'c')
  endif
endif
if cc.check_header('sys/param.h')
  add_project_arguments('-DHAVE_SYS_PARAM_H', language: 'c')
endif
if cc.check_header('signal.h')
  add_project_arguments('-DHAVE_SIGNAL_H', language: 'c')
  if cc.has_function('raise', prefix : '#include <signal.h>')
    add_project_arguments('-DHAVE_RAISE', language: 'c')
  endif
endif
if cc.has_function('posix_memalign', prefix : '#include <stdlib.h>')
  add_project_arguments('-DHAVE_POSIX_MEMALIGN', language: 'c')
endif
if cc.has_function('memset_s', prefix : '#include <string.h>')
  add_project_arguments('-DHAVE_MEMSET_S', language: 'c')
endif
if cc.has_function('explicit_bzero', prefix : '#include <string.h>')
  add_project_arguments('-DHAVE_EXPLICIT_BZERO', language: 'c')
endif
if cc.has_function('memset_explicit', prefix : '#include <string.h>')
  add_project_arguments('-DHAVE_MEMSET_EXPLICIT', language: 'c')
endif
if cc.has_function('explicit_memset', prefix : '#include <string.h>')
  add_project_arguments('-DHAVE_EXPLICIT_MEMSET', language: 'c')
endif
if cc.has_function_attribute('weak')
  add_project_arguments('-DHAVE_WEAK_SYMBOLS', language: 'c')
endif

py = import('python').find_installation(pure: false)
py_dep = py.dependency()

cy = meson.get_compiler('cython')
cython = find_program(cy.cmd_array()[0])

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
