cython_args = []

cython_c_args = cc.get_supported_arguments(
  '-Wbad-function-cast',
  '-Wcast-qual',
  '-Wdiv-by-zero',
  '-Wfloat-equal',
  '-Wmissing-declarations',
  '-Wmissing-prototypes',
  '-Wnested-externs',
  '-Wno-type-limits',

  '-Wno-unknown-pragmas',
  '-Wpointer-arith',
  '-Wstrict-prototypes',
  '-Wswitch-enum',
  '-fno-exceptions',

  '-mtune=native',
)

_cython_tree_cydrogen = [
  fs.copyfile('__init__.py'),
  fs.copyfile('_basekey.pxd'),
  fs.copyfile('_context.pxd'),
  fs.copyfile('_decls.pxd'),
  fs.copyfile('_exceptions.pxd'),
  fs.copyfile('_hash.pxd'),
  fs.copyfile('_masterkey.pxd'),
  fs.copyfile('_secretbox.pxd'),
  fs.copyfile('_sign.pxd'),
  fs.copyfile('_utils.pxd'),
]

cydrogen_pyx_sources = [
  ['_basekey', ['_basekey.pyx']],
  ['_context', ['_context.pyx']],
  ['_exceptions', ['_exceptions.pyx']],
  ['_hash', ['_hash.pyx']],
  ['_masterkey', ['_masterkey.pyx']],
  ['_secretbox', ['_secretbox.pyx']],
  ['_sign', ['_sign.pyx']],
  ['_utils', ['_utils.pyx', 'cyutils.c', 'cyd_memcpy_s.c']],
  ['_decls', ['_decls.pyx', 'src/hydrogen.c']],
]

cydrogen_dir = py.get_install_dir() / 'cydrogen'

# Generate version.py for sdist
meson.add_dist_script(
   ['../tools/gitversion.py', '--meson-dist', '--write', 'cydrogen/version.py']
)

if not fs.exists('version.py')
  generate_version = custom_target(
    'generate-version',
    install: true,
    build_always_stale: true,
    build_by_default: true,
    output: 'version.py',
    input: '../tools/gitversion.py',
    command: ['../tools/gitversion.py', '--meson-dist', '--write', 'cydrogen/version.py'],
    install_dir: cydrogen_dir,
    install_tag: 'python-runtime',
  )
else
  # When building from sdist, version.py exists and should be included
  py.install_sources(['version.py'], subdir : 'cydrogen')
endif

cython_shared_src = custom_target(
  install: false,
  output: '_cyutility.c',
  command: [
    cython, '--generate-shared=' + meson.current_build_dir()/'_cyutility.c'
  ],
)

cython_shared_module = py.extension_module('_cyutility',
  cython_shared_src,
  subdir: 'cydrogen',
  cython_args: cython_args,
  install: true,
)

cython_args += ['--shared=cydrogen._cyutility']

foreach gen: cydrogen_pyx_sources
  py.extension_module(gen[0],
    [gen[1], _cython_tree_cydrogen],
    c_args: cython_c_args,
    link_args: version_link_args,
    dependencies: [py_dep],
    install: true,
    subdir: 'cydrogen',
    cython_args: cython_args,
    include_directories: 'src',
  )
endforeach

python_sources = [
  '__init__.py',
  '__init__.pyi',
  '_basekey.pxd',
  '_basekey.pyi',
  '_context.pxd',
  '_context.pyi',
  '_decls.pxd',
  '_decls.pyi',
  '_exceptions.pxd',
  '_exceptions.pyi',
  '_hash.pxd',
  '_hash.pyi',
  '_masterkey.pxd',
  '_masterkey.pyi',
  '_secretbox.pxd',
  '_secretbox.pyi',
  '_sign.pxd',
  '_sign.pyi',
  '_utils.pxd',
  '_utils.pyi',
  '_decls.pxd',
  '_decls.pyi',
]

py.install_sources(
  python_sources,
  pure: false,
  subdir: 'cydrogen'
)
