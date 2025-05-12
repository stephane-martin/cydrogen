# cython: language_level=3

from ._decls cimport hydro_init


def hynit():
    if hydro_init() != 0:
        raise RuntimeError("Failed to initialize libhydrogen")
