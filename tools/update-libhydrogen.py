# /usr/bin/env python

"""
This script updates the libhydrogen library by downloading and copying the sources in cydrogen's source tree.
"""

import argparse
import pathlib
import shutil
import subprocess
import tempfile

ROOT_DIR = pathlib.Path(__file__).resolve().parent.parent
TARGET_DIR = ROOT_DIR / "cydrogen" / "src"
LIBHYDROGEN_REPO = "https://github.com/jedisct1/libhydrogen.git"
SOURCE_FILES = ["hydrogen.c", "hydrogen.h", "LICENSE", "CITATION.cff"]
SOURCE_DIRS = ["impl"]


def main() -> None:
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

    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is not installed or not found in PATH")

    # work in a temporary directory
    with tempfile.TemporaryDirectory() as tmpdir:
        abs_tmpdir = pathlib.Path(tmpdir).resolve()
        # clone the libhydrogen repository
        subprocess.run(  # noqa: S603
            [git, "clone", "-b", branch, LIBHYDROGEN_REPO],
            cwd=tmpdir,
            check=True,
        )
        # copy the sources to the ROOT_DIR
        for src_file in SOURCE_FILES:
            src_path = abs_tmpdir / "libhydrogen" / src_file
            dst_path = TARGET_DIR / src_file
            shutil.copy(src_path, dst_path)
        for src_dir in SOURCE_DIRS:
            src_path = abs_tmpdir / "libhydrogen" / src_dir
            dst_path = TARGET_DIR / src_dir
            shutil.copytree(src_path, dst_path, dirs_exist_ok=True)


if __name__ == "__main__":
    main()
