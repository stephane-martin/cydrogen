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

subdir('cydrogen')
