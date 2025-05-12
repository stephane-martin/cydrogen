# /usr/bin/env python
# -*- coding: utf-8 -*-

"""
This script updates the libhydrogen library by downloading and copying the sources in cydrogen's source tree.
"""

import argparse
import shutil
import subprocess
import tempfile
from os.path import abspath, dirname, join

THIS_DIR = dirname(abspath(__file__))
ROOT_DIR = dirname(THIS_DIR)
TARGET_DIR = join(ROOT_DIR, "cydrogen", "src")
LIBHYDROGEN_REPO = "https://github.com/jedisct1/libhydrogen.git"
SOURCE_FILES = ["hydrogen.c", "hydrogen.h", "LICENSE", "CITATION.cff"]
SOURCE_DIRS = ["impl"]


def main():
    parser = argparse.ArgumentParser(description="Update libhydrogen library.")
    # add an argument for the optional branch name
    parser.add_argument(
        "-b",
        "--branch",
        default="master",
        help="The branch to update from (default: master)",
    )
    args = parser.parse_args()
    branch = args.branch or "master"
    # work in a temporary directory
    with tempfile.TemporaryDirectory() as tmpdir:
        # clone the libhydrogen repository
        subprocess.run(
            ["git", "clone", "-b", branch, LIBHYDROGEN_REPO],
            cwd=tmpdir,
            check=True,
        )
        # copy the sources to the ROOT_DIR
        for src_file in SOURCE_FILES:
            src_path = join(tmpdir, "libhydrogen", src_file)
            dst_path = join(TARGET_DIR, src_file)
            shutil.copy(src_path, dst_path)
        for src_dir in SOURCE_DIRS:
            src_path = join(tmpdir, "libhydrogen", src_dir)
            dst_path = join(TARGET_DIR, src_dir)
            shutil.copytree(src_path, dst_path, dirs_exist_ok=True)


if __name__ == "__main__":
    main()
