#include <Python.h>
#include <stdint.h>

Py_hash_t cy_hash_buffer(const void *buf, Py_ssize_t len, uint32_t prefix, uint32_t suffix);
