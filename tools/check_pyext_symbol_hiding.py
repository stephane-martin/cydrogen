#!/usr/bin/env python

import pathlib
import shutil
import subprocess
import sys
import tempfile
import zipfile


def count_symbols(filename: pathlib.Path) -> int:
    """Count the number of text symbols in a shared object file."""
    nm = shutil.which("nm")
    if nm is None:
        print("Error: 'nm' command not found. Please install binutils.")
        sys.exit(1)
    result = subprocess.run([nm, "-D", "--defined-only", str(filename)], capture_output=True, text=True, check=True)  # noqa: S603
    return len(result.stdout.splitlines())


def check_symbols_in_wheel(filename: pathlib.Path) -> dict[str, int]:
    # extract the wheel as zip file in a temporary directory
    with tempfile.TemporaryDirectory() as tmpdirname:
        with zipfile.ZipFile(filename, "r") as zip_ref:
            zip_ref.extractall(tmpdirname)

        # find all .so files in the extracted directory
        so_files = pathlib.Path(tmpdirname).glob("**/*.so")

        # check each .so file for text symbols
        results = {}
        for so_file in so_files:
            abs_so_file = pathlib.Path(tmpdirname) / so_file
            print(f"  - Checking {abs_so_file.name}")
            num_symbols = count_symbols(abs_so_file)
            if num_symbols > 1:
                results[abs_so_file.name] = num_symbols
        return results


def check_directory(dirname: pathlib.Path) -> dict[str, dict[str, int]]:
    # find all .whl files in the directory
    wheel_files = dirname.glob("**/*.whl")

    # check each wheel file for text symbols
    results = {}
    for wheel_file in wheel_files:
        abs_wheel_file = dirname / wheel_file
        print(f"- Checking {abs_wheel_file.name}")
        symbols = check_symbols_in_wheel(abs_wheel_file)
        if symbols:
            results[abs_wheel_file.name] = symbols
    return results


def main() -> None:
    # take directory to check from posargs
    if len(sys.argv) != 2:
        print("Usage: check_pyext_symbol_hiding.py <directory>")
        sys.exit(1)
    directory = pathlib.Path(sys.argv[1]).resolve()
    if not directory.exists():
        print(f"Error: {directory} does not exist.")
        sys.exit(1)
    if not directory.is_dir():
        print(f"Error: {directory} is not a directory.")
        sys.exit(1)
    results = check_directory(directory)
    print()
    if results:
        for wheel_file, symbols in results.items():
            for so_file, num_symbols in symbols.items():
                print(f"{wheel_file}: {so_file} has {num_symbols} text symbols")
        sys.exit(1)
    else:
        print("OK")


if __name__ == "__main__":
    main()
