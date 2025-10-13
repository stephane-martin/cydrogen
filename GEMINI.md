# Cydrogen Project Overview

This document provides a comprehensive overview of the Cydrogen project, its structure, and development workflows.

## Project Purpose

Cydrogen is a Python/Cython wrapper for the `libhydrogen` cryptographic library. It aims to provide a Pythonic interface to the powerful and easy-to-use `libhydrogen` library.

## Technologies and Architecture

-   **Core Language:** Python with Cython for C interoperability.
-   **Build System:** Meson is used to build the Cython extensions and the underlying C code. `meson-python` is used as the build backend.
-   **C Library:** It wraps `libhydrogen`, a small, easy-to-use, and hard-to-misuse cryptographic library.
-   **Dependency Management:** Project dependencies are managed in `pyproject.toml`.
-   **Task Automation:** `nox` is used for automating development tasks like linting, testing, and building.

## Development Workflow

The project uses a set of standardized commands for common development tasks, all managed through `nox`.

### Initial Setup

To set up the development environment, run the following command. This will install all necessary dependencies for development, testing, linting, and building.

```bash
nox -s develop
```

### Building the Project

To build the project, including the sdist and wheel, run:

```bash
nox -s build
```

You can also build the sdist and wheel separately:

```bash
nox -s build_sdist
nox -s build_wheel
```

To build only for the latest Python version (3.14):

```bash
nox -s build-3.14
```

NOTE: the build process relies on `meson` and `meson-python`, so only files committed to the git repository will be included in the build.
So make sure to commit your changes before building.

### Running Tests

The project uses `pytest` for testing. To run the test suite:

```bash
nox -s test
```

To run tests only for the latest Python version (3.14):

```bash
nox -s test-3.14
```

NOTE: running the tests will build the project in an isolated environment, so there is no need to build the project separately before testing.
But only files committed to the git repository will be included in the build. So make sure to commit your changes before running the tests.

### Linting and Code Style

The project uses a comprehensive set of linters to ensure code quality and consistency. The following tools are used:

-   `ruff` for general Python linting and formatting.
-   `mypy` for static type checking.
-   `cython-lint` for linting Cython code.
-   `shellcheck` for shell scripts.
-   `actionlint` for GitHub Actions workflows.
-   `zizmor` for static analysis of the Github Actions workflows.
-   `typos` for checking for typos.

To run all linters:

```bash
nox -s lint
```

### Building Documentation

The project uses `mkdocs` to generate documentation. To build the documentation:

```bash
nox -s docs
```

The generated documentation will be in the `site` directory.

## Project Structure

-   `cydrogen/`: The main source directory for the Python/Cython code.
    -   `_utils.pyx`, `_utils.pxd`: Technical utility functions and classes used by other modules. In particular:
        -   `cydrogen.SafeMemory`: A class to manage sensitive data in memory. SafeMemory is based on guarded heap allocations. It relies on `cyutils.c`.
        -   I/O classes used as defensive programming to manage short reads/writes when dealing with files or sockets.
    -   `_decls.pyx`, `_decls.pxd`: Cython low level wrappers for the `libhydrogen` C functions and types. Everything we want to use from `libhydrogen` must be declared here.
        libhydrogen functions are wrapped into cython functions that take memeryviews arguments instead of raw pointers.
        Other modules should not import anything from `libhydrogen` directly, but only use the functions declared here to provide higher level abstractions.
    -   `cyutils.c`, `cyutils.h`: low level C code for guarded heap allocations, zeroing memory, marking memory as readonly, etc.
    -   `fnv.c`, `fnv.h`: C implementation of a FNV hash function (used in Python < 3.14 to implement `__hash__` for a few classes)
    -   `_basekey.pxd`, `_basekey.pyx`: Base class to represent cryptographic keys. Relies on SafeMemory to manage the key material.
    -   `_hash.pxd`, `_hash.pyx`: Hashing functions and classes.
    -   `_secretbox.pxd`, `_secretbox.pyx`: Secret-key authenticated encryption.
    -   `_sign.pxd`, `_sign.pyx`: Public-key signatures.
    -   `_masterkey.pxd`, `_masterkey.pyx`: Master keys and key derivation functions.
    -   `_kx_n.pxd`, `_kx_n.pyx`: Public-key authenticated key exchange.
    -   `_context.pxd`, `_context.pyx`: Contexts for domain separation.
    -   `_datastructs.pxd`, `_datastructs.pyx`: Data structures used by the networking part of cydrogen.
    -   `_networking.pxd`, `_networking.pyx`: Utils supporting the networking part of cydrogen.
        -   low level memory management classes such as `BytearrayBuilder` and `ReadBuffers`
        -   specialized sync and async message queues
        -   an implementation of a many readers / single writer lock
    -   `networking.py`: "sans-IO" protocol implementation of network protocols based on libhydrogen primitives.
    -   `sync_networking.py`: Synchronous network clients and servers based on threads.
    -   `async_networking.py`: Asynchronous network clients and servers based on asyncio.
    -   `src/`: The `libhydrogen` C source code, copied from the `libhydrogen` project.
    -   `meson.build`: The Meson build script for building the Cython extensions and the `libhydrogen` C code.
    -   `*.pyi`: Type stubs for the Cython modules.
-   `tests/`: Contains the test suite.
-   `tools/`: Contains helper scripts for development and release.
-   `docs/`: Contains the documentation source files.
-   `pyproject.toml`: The main configuration file for the project, including dependencies, build system configuration, and tool configurations.
-   `meson.build`: The Meson build script for the project.
-   `noxfile.py`: The `nox` configuration file for automating development tasks.
