#!/usr/bin/env python3
"""Patch a Cowrie ``fs.pickle`` so planted bait files appear in the fake
filesystem (so ``ls`` lists them and ``cat`` returns the honeyfs content).

Usage:
    add_baits_to_fs.py <fs.pickle> <vpath>=<realfile>[:<octal_mode>] ...

Example:
    add_baits_to_fs.py /cowrie/cowrie-git/share/cowrie/fs.pickle \
        /tmp/database_backup.sql=/cowrie/cowrie-git/honeyfs/tmp/database_backup.sql:644 \
        /root/.ssh/id_rsa=/cowrie/cowrie-git/honeyfs/root/.ssh/id_rsa:600

The bait *content* must already exist at <realfile> under the honeyfs tree.
"""
import os
import pickle
import sys
import time

# Cowrie filesystem record layout. Prefer the values from the installed cowrie
# package (authoritative across versions); fall back to the documented literals.
try:
    from cowrie.shell.fs import (  # type: ignore
        A_CONTENTS,
        A_NAME,
        A_TYPE,
        T_DIR,
        T_FILE,
    )
    print("[add_baits] using cowrie.shell.fs constants", flush=True)
except Exception as exc:  # pragma: no cover - depends on image internals
    print(f"[add_baits] cowrie import failed ({exc}); using literal constants", flush=True)
    A_NAME, A_TYPE, A_CONTENTS = 0, 1, 7
    T_DIR, T_FILE = 0, 2

A_UID, A_GID, A_SIZE, A_MODE, A_CTIME, A_TARGET, A_REALFILE = 2, 3, 4, 5, 6, 8, 9


def _children(dir_entry):
    if dir_entry[A_CONTENTS] is None:
        dir_entry[A_CONTENTS] = []
    return dir_entry[A_CONTENTS]


def _find(dir_entry, name):
    for child in _children(dir_entry):
        if child[A_NAME] == name:
            return child
    return None


def _ensure_dir(parent, name):
    existing = _find(parent, name)
    if existing is not None and existing[A_TYPE] == T_DIR:
        return existing
    entry = [name, T_DIR, 0, 0, 4096, 0o40755, int(time.time()), [], None, None]
    _children(parent).append(entry)
    return entry


def _add_file(parent, name, realfile, mode):
    # Drop any pre-existing entry with the same name, then append the bait.
    parent[A_CONTENTS] = [c for c in _children(parent) if c[A_NAME] != name]
    size = os.path.getsize(realfile) if os.path.exists(realfile) else 0
    entry = [name, T_FILE, 0, 0, size, 0o100000 | mode, int(time.time()), None, None, realfile]
    parent[A_CONTENTS].append(entry)


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 1

    fs_path = argv[1]
    with open(fs_path, "rb") as handle:
        root = pickle.load(handle)

    for spec in argv[2:]:
        vpath, _, realpart = spec.partition("=")
        # Parse an optional trailing ":<octal_mode>". Use rpartition so a colon
        # inside the path (e.g. a Windows drive letter) is not mistaken for it.
        head, sep, tail = realpart.rpartition(":")
        if sep and tail.isdigit():
            realfile, mode = head, int(tail, 8)
        else:
            realfile, mode = realpart, 0o644
        parts = [p for p in vpath.split("/") if p]
        node = root
        for directory in parts[:-1]:
            node = _ensure_dir(node, directory)
        _add_file(node, parts[-1], realfile, mode)
        print(f"[add_baits] planted {vpath} -> {realfile} (mode {oct(mode)})", flush=True)

    with open(fs_path, "wb") as handle:
        pickle.dump(root, handle)
    print(f"[add_baits] wrote {fs_path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
