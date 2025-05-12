project(
  'cydrogen',
  'c', 'cython',
  license: 'Apache-2.0',
  meson_version: '>= 1.8.0',
  version: '0.1.0',
  default_options: [
    'buildtype=release',
  ]
)

cc = meson.get_compiler('c')
py = import('python').find_installation(pure: false)
py_dep = py.dependency()
fs = import('fs')

subdir('cydrogen')
