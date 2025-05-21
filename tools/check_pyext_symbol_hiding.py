#!/usr/bin/env python

import glob
import os
import subprocess
import sys
import tempfile
import zipfile
from os.path import basename, join


def count_symbols(filename) -> int:
    """Count the number of text symbols in a shared object file."""
    result = subprocess.run(["nm", "-D", "--defined-only", str(filename)], capture_output=True, text=True, check=True)
    return len(result.stdout.splitlines())


def check_symbols_in_wheel(filename):
    # extract the wheel as zip file in a temporary directory
    with tempfile.TemporaryDirectory() as tmpdirname:
        with zipfile.ZipFile(filename, "r") as zip_ref:
            zip_ref.extractall(tmpdirname)

        # find all .so files in the extracted directory
        so_files = glob.glob("**/*.so", recursive=True, root_dir=tmpdirname)

        # check each .so file for text symbols
        results = dict()
        for so_file in so_files:
            so_file = join(tmpdirname, so_file)
            print(f"  - Checking {basename(so_file)}")
            num_symbols = count_symbols(so_file)
            if num_symbols > 1:
                results[basename(so_file)] = num_symbols
        return results


def check_directory(dirname):
    # find all .whl files in the directory
    wheel_files = glob.glob("**/*.whl", recursive=True, root_dir=dirname)

    # check each wheel file for text symbols
    results = dict()
    for wheel_file in wheel_files:
        wheel_file = join(dirname, wheel_file)
        print(f"- Checking {basename(wheel_file)}")
        symbols = check_symbols_in_wheel(wheel_file)
        if symbols:
            results[basename(wheel_file)] = symbols
    return results


def main():
    # take directory to check from posargs
    if len(sys.argv) != 2:
        print("Usage: check_pyext_symbol_hiding.py <directory>")
        sys.exit(1)
    directory = sys.argv[1]
    if not os.path.exists(directory):
        print(f"Error: {directory} does not exist.")
        sys.exit(1)
    if not os.path.isdir(directory):
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
