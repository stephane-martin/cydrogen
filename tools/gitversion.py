#!/usr/bin/env python
import argparse
import os
import os.path
import pathlib
import shutil
import subprocess
import textwrap

ROOT = pathlib.Path(__file__).resolve().parent.parent


def init_version() -> str:
    init = ROOT / "pyproject.toml"
    with init.open(mode="rt", encoding="utf-8") as fid:
        data = fid.readlines()
    version_line = next(line for line in data if line.startswith("version ="))
    version = version_line.strip().split(" = ")[1]
    return version.replace('"', "").replace("'", "")


def git_version(version: str) -> tuple[str, str]:
    # Append last commit date and hash to dev version information if available
    git_hash = ""
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git command not found. Please install git to use this script.")
    try:
        p = subprocess.Popen(  # noqa: S603
            [git, "log", "-1", '--format="%H %aI"'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(ROOT),
        )
    except FileNotFoundError:
        pass
    else:
        out, err = p.communicate()
        if p.returncode == 0:
            git_hash, git_date = out.decode("utf-8").strip().replace('"', "").split("T")[0].replace("-", "").split()

            # Only attach git tag to development versions
            if "-dev" in version:
                version += f"+git{git_date}.{git_hash[:7]}"
    return version, git_hash


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", help="Save version to this file")
    parser.add_argument("--meson-dist", help="Output path is relative to MESON_DIST_ROOT", action="store_true")
    args = parser.parse_args()

    version, git_hash = git_version(init_version())

    template = textwrap.dedent(f'''
        """
        Module to expose more detailed version info for the installed `cydrogen`
        """
        version = "{version}"
        full_version = version
        short_version = version.split("-dev")[0]
        git_revision = "{git_hash}"
        release = "-dev" not in version and "+" not in version

        if not release:
            version = full_version''').strip()
    template += "\n"

    if args.write:
        outfile = pathlib.Path(args.write).resolve()
        if args.meson_dist:
            meson_dist_root = os.environ.get("MESON_DIST_ROOT", "")
            outfile = pathlib.Path(meson_dist_root) / outfile if meson_dist_root else outfile

        with outfile.open("wt", encoding="utf-8") as f:
            f.write(template)
    else:
        print(version)
