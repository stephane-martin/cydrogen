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
  fs.copyfile('_random.pxd'),
  fs.copyfile('_secretbox.pxd'),
  fs.copyfile('_sign.pxd'),
  fs.copyfile('_utils.pxd'),
]

cydrogen_pyx_sources = [
  ['_basekey', ['_basekey.pyx', 'src/hydrogen.c']],
  ['_context', ['_context.pyx', 'src/hydrogen.c']],
  ['_cydrogen', ['_cydrogen.pyx', 'src/hydrogen.c']],
  ['_exceptions', '_exceptions.pyx'],
  ['_hash', ['_hash.pyx', 'src/hydrogen.c']],
  ['_masterkey', ['_masterkey.pyx', 'src/hydrogen.c']],
  ['_random', ['_random.pyx', 'src/hydrogen.c']],
  ['_secretbox', ['_secretbox.pyx', 'src/hydrogen.c']],
  ['_sign', ['_sign.pyx', 'src/hydrogen.c']],
  ['_utils', '_utils.pyx'],
]

foreach gen: cydrogen_pyx_sources
  py.extension_module(gen[0],
    [gen[1], _cython_tree_cydrogen],
    c_args: cython_c_args,
    dependencies: [py_dep],
    install: true,
    subdir: 'cydrogen',
    cython_args: cython_args,
    include_directories: 'src',
  )
endforeach

python_sources = [
  '__init__.py',
  '_basekey.pxd',
  '_context.pxd',
  '_decls.pxd',
  '_exceptions.pxd',
  '_hash.pxd',
  '_masterkey.pxd',
  '_random.pxd',
  '_secretbox.pxd',
  '_sign.pxd',
  '_utils.pxd',
]

py.install_sources(
  python_sources,
  pure: false,
  subdir: 'cydrogen'
)
