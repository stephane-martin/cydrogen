# Cydrogen Project Overview

This document provides a comprehensive overview of the Cydrogen project, its structure, and development workflows.

## Project Purpose

Cydrogen is a Python/Cython wrapper for the `libhydrogen` cryptographic library. It aims to provide a Pythonic interface to the powerful and easy-to-use `libhydrogen` library.

## Technologies and Architecture

*   **Core Language:** Python with Cython for C interoperability.
*   **Build System:** Meson is used to build the Cython extensions and the underlying C code. `meson-python` is used as the build backend.
*   **C Library:** It wraps `libhydrogen`, a small, easy-to-use, and hard-to-misuse cryptographic library.
*   **Dependency Management:** Project dependencies are managed in `pyproject.toml`.
*   **Task Automation:** `nox` is used for automating development tasks like linting, testing, and building.

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

### Running Tests

The project uses `pytest` for testing. To run the test suite:

```bash
nox -s test
```

### Linting and Code Style

The project uses a comprehensive set of linters to ensure code quality and consistency. The following tools are used:

*   `ruff` for general Python linting and formatting.
*   `mypy` for static type checking.
*   `cython-lint` for linting Cython code.
*   `shellcheck` for shell scripts.
*   `actionlint` for GitHub Actions workflows.
*   `zizmor` for static analysis of the Github Actions workflows.
*   `typos` for checking for typos.

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

*   `cydrogen/`: The main source directory for the Python/Cython code.
    *   `src/`: Contains the `libhydrogen` source code.
    *   `*.pyx`, `*.pxd`: Cython source files.
*   `tests/`: Contains the test suite.
*   `tools/`: Contains helper scripts for development and release.
*   `docs/`: Contains the documentation source files.
*   `pyproject.toml`: The main configuration file for the project, including dependencies, build system configuration, and tool configurations.
*   `meson.build`: The Meson build script for the project.
*   `noxfile.py`: The `nox` configuration file for automating development tasks.
