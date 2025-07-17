#!/usr/bin/env python

import argparse
import pathlib
import sys
from itertools import chain

latin1_letters = {chr(cp) for cp in range(192, 256)}
greek_letters = set("αβγδεζηθικλμνξoπρστυϕχψω" + "ΓΔΘΛΞΠΣϒΦΨΩ")
box_drawing_chars = {chr(cp) for cp in range(0x2500, 0x2580)}
allowed = latin1_letters | greek_letters | box_drawing_chars


def check_unicode() -> int:
    # File encoding regular expression from PEP-263.
    root_dir = pathlib.Path(__file__).resolve().parent.parent

    nbad = 0

    globs = [
        "cydrogen/**/*.py",
        "tools/**/*.py",
        "cydrogen/**/*.pyx",
        "cydrogen/**/*.px[di]",
    ]

    res = [list(root_dir.glob(g)) for g in globs]
    names = list(chain(*res))
    names = [name.resolve() for name in names]
    names.append(root_dir / "pyproject.toml")
    names.append(root_dir / "noxfile.py")

    for name in names:
        # Read the file as bytes, and check for any bytes greater than 127.
        with name.open("rb") as f:
            content = f.read()
        if len(content) == 0:
            continue
        if max(content) > 127:
            bcontent = content.decode(encoding="utf-8")

            out = []
            for n, line in enumerate(bcontent.splitlines()):
                for pos, char in enumerate(line):
                    cp = ord(char)
                    if cp > 127:
                        msg = f"... line {n + 1}, position {pos + 1}: character '{char}', code point U+{cp:04X}"
                        if char not in allowed:
                            out.append(msg)
            if len(out) > 0:
                nbad += 1
                print(f"{name}")
                for msg in out:
                    print(msg)
    return nbad


if __name__ == "__main__":
    descr = "Check for disallowed Unicode characters source code."
    parser = argparse.ArgumentParser(description=descr)
    args = parser.parse_args()
    sys.exit(check_unicode() > 0)
