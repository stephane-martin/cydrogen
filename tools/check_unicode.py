#!/usr/bin/env python

import argparse
import os
import sys
from glob import iglob
from itertools import chain
from os.path import dirname

latin1_letters = set(chr(cp) for cp in range(192, 256))
greek_letters = set("αβγδεζηθικλμνξoπρστυϕχψω" + "ΓΔΘΛΞΠΣϒΦΨΩ")
box_drawing_chars = set(chr(cp) for cp in range(0x2500, 0x2580))
allowed = latin1_letters | greek_letters | box_drawing_chars


def check_unicode():
    # File encoding regular expression from PEP-263.
    root_dir = dirname(dirname(__file__))

    nbad = 0
    for name in chain(
        iglob(os.path.join(root_dir, "cydrogen/**/*.py"), recursive=True),
        iglob(os.path.join(root_dir, "tools/**/*.py"), recursive=True),
        iglob(os.path.join(root_dir, "cydrogen/**/*.pyx"), recursive=True),
        iglob(os.path.join(root_dir, "cydrogen/**/*.px[di]"), recursive=True),
        ["pyproject.toml", "noxfile.py"],
    ):
        # print(f"- {name}")
        # Read the file as bytes, and check for any bytes greater than 127.
        with open(name, "rb") as f:
            content = f.read()
        if len(content) == 0:
            continue
        if max(content) > 127:
            content = content.decode(encoding="utf-8")

            out = []
            for n, line in enumerate(content.splitlines()):
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
