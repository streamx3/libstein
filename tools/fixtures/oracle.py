#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Portable oracle for filesystem reader fixtures (the `find -printf` recipe in the
shell generators needs GNU find, which macOS lacks). Prints, for a mounted tree:

  <t> <size> <relative path>      t = f (file), d (directory), l (symlink)
  sha256 <hex> <relative path>    for every regular file
  link <relative path> -> <target> for every symlink

usage: oracle.py <mountpoint> [--skip NAME ...]   (names matched at any depth)
"""
import hashlib
import os
import sys

sys.stdout.reconfigure(encoding="utf-8")
root = sys.argv[1]
skip = set()
if "--skip" in sys.argv:
    skip = set(sys.argv[sys.argv.index("--skip") + 1:])
entries, shas, links = [], [], []
for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
    dirnames[:] = sorted(d for d in dirnames if d not in skip)
    for d in dirnames:
        entries.append(("d", os.lstat(os.path.join(dirpath, d)).st_size, os.path.relpath(os.path.join(dirpath, d), root)))
    for f in sorted(filenames):
        if f in skip:
            continue
        p = os.path.join(dirpath, f)
        rel = os.path.relpath(p, root)
        st = os.lstat(p)
        if os.path.islink(p):
            entries.append(("l", st.st_size, rel))
            links.append((rel, os.readlink(p)))
        else:
            entries.append(("f", st.st_size, rel))
            with open(p, "rb") as h:
                shas.append((hashlib.sha256(h.read()).hexdigest(), rel))
for t, size, rel in sorted(entries, key=lambda e: e[2]):
    print("%s %d %s" % (t, size, rel))
for sha, rel in sorted(shas, key=lambda e: e[1]):
    print("sha256 %s %s" % (sha, rel))
for rel, target in sorted(links):
    print("link %s -> %s" % (rel, target))
