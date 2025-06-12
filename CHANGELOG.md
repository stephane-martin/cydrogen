# Changelog

All notable changes to `cydrogen` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v0.0.10 - 2025-06-12

### Fixed

- zizmor defects.

## v0.0.9 - 2025-06-12

### Fixed

- permissions for release workflow.

## v0.0.8 - 2025-06-12

### Fixed

- permissions for ci_master.

## v0.0.7 - 2025-06-12

### Added

- MasterKey.gen_random_buffer to generate pseudo-random data.
- pad and unpad functions.
- key exchange using the N variant.

## v0.0.6 - 2025-06-06

### Security

- Generate attestations of sdist and wheels for Github.

### Added

- Use cython --shared to make binaries smaller.

## v0.0.5 - 2025-06-05

### Added

- Expose `pad` and `unpad` functions ([#32](https://github.com/stephane-martin/cydrogen/issues/32)).

## v0.0.4 - 2025-06-04

### Added

- Initial release published on [PyPI](https://pypi.org/project/cydrogen/).

