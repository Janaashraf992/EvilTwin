#!/usr/bin/env python3
"""Locate Cowrie's ``fs.pickle``, stage honeyfs bait files, and register them so
they appear in ``ls`` and ``cat`` returns their bytes.

Pure Python (no shell) so it works on the shell-less ``cowrie/cowrie`` base
image. Invoked from the Dockerfile via the exec form::

    RUN ["/cowrie/cowrie-env/bin/python", "/tmp/plant_baits.py"]

Bait *content* is staged at ``/tmp/baits-honeyfs/<rel>`` by an earlier
``COPY honeyfs/ /tmp/baits-honeyfs/`` instruction.
"""
import os
import pickle
import shutil
import sys
import time

STAGE = "/tmp/baits-honeyfs"

# (vpath in fake fs, path relative to honeyfs/STAGE, octal mode, age in days)
# Baits are scattered across realistic locations (not piled in /root) and given
# staggered ages so they don't all share an identical, freshly-planted ctime.
BAITS = [
    ("/tmp/database_backup.sql", "tmp/database_backup.sql", 0o644, 2),
    ("/root/.ssh/id_rsa", "root/.ssh/id_rsa", 0o600, 420),
    ("/root/.bash_history", "root/.bash_history", 0o600, 1),
    ("/home/deploy/.aws/credentials", "home/deploy/.aws/credentials", 0o600, 95),
    ("/opt/app/.env", "opt/app/.env", 0o640, 60),
    ("/var/backups/db/prod_db_dump.sql", "var/backups/db/prod_db_dump.sql", 0o644, 7),
]

# Cowrie fs.pickle record layout. Prefer the installed package constants;
# fall back to the documented literals if the import is unavailable.
try:
    from cowrie.shell.fs import (  # type: ignore
        A_CONTENTS,
        A_NAME,
        A_TYPE,
        T_DIR,
        T_FILE,
    )
    print("[plant] using cowrie.shell.fs constants", flush=True)
except Exception as exc:  # pragma: no cover - depends on image internals
    print(f"[plant] cowrie import failed ({exc}); using literal constants", flush=True)
    A_NAME, A_TYPE, A_CONTENTS = 0, 1, 7
    T_DIR, T_FILE = 0, 2


def find_fs_pickle():
    known = "/cowrie/cowrie-git/share/cowrie/fs.pickle"
    if os.path.exists(known):
        return known
    fallback = None
    for root, _dirs, files in os.walk("/"):
        if "fs.pickle" in files:
            candidate = os.path.join(root, "fs.pickle")
            if os.path.join("share", "cowrie") in candidate:
                return candidate
            fallback = fallback or candidate
    return fallback


def _children(entry):
    if entry[A_CONTENTS] is None:
        entry[A_CONTENTS] = []
    return entry[A_CONTENTS]


def _find(entry, name):
    for child in _children(entry):
        if child[A_NAME] == name:
            return child
    return None


def _ensure_dir(parent, name, ctime):
    existing = _find(parent, name)
    if existing is not None and existing[A_TYPE] == T_DIR:
        return existing
    entry = [name, T_DIR, 0, 0, 4096, 0o40755, ctime, [], None, None]
    _children(parent).append(entry)
    return entry


def _add_file(parent, name, realfile, mode, ctime):
    parent[A_CONTENTS] = [c for c in _children(parent) if c[A_NAME] != name]
    size = os.path.getsize(realfile) if os.path.exists(realfile) else 0
    entry = [name, T_FILE, 0, 0, size, 0o100000 | mode, ctime, None, None, realfile]
    parent[A_CONTENTS].append(entry)


def main():
    fsp = find_fs_pickle()
    if not fsp:
        print("ERROR: fs.pickle not found", file=sys.stderr)
        return 1

    home_dir = os.path.dirname(os.path.dirname(os.path.dirname(fsp)))
    honeyfs = os.path.join(home_dir, "honeyfs")
    print(f"[plant] fs.pickle={fsp}  home={home_dir}  honeyfs={honeyfs}", flush=True)

    with open(fsp, "rb") as handle:
        root = pickle.load(handle)

    now = int(time.time())
    dir_ctime = now - 500 * 86400  # parent dirs look long-established

    for vpath, rel, mode, age_days in BAITS:
        src = os.path.join(STAGE, rel)
        dst = os.path.join(honeyfs, rel)
        if not os.path.exists(src):
            print(f"[plant] WARNING: missing staged bait {src}, skipping", flush=True)
            continue
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copyfile(src, dst)
        os.chmod(dst, mode)

        file_ctime = now - age_days * 86400
        parts = [p for p in vpath.split("/") if p]
        node = root
        for directory in parts[:-1]:
            node = _ensure_dir(node, directory, dir_ctime)
        _add_file(node, parts[-1], dst, mode, file_ctime)
        print(f"[plant] {vpath} -> {dst} (mode {oct(mode)}, age {age_days}d)", flush=True)

    with open(fsp, "wb") as handle:
        pickle.dump(root, handle)
    print(f"[plant] wrote {fsp}", flush=True)

    # Best-effort: hand ownership back to the cowrie runtime user.
    try:
        targets = [fsp]
        for current, dirs, files in os.walk(honeyfs):
            targets.append(current)
            targets.extend(os.path.join(current, f) for f in files)
        for path in targets:
            try:
                shutil.chown(path, user="cowrie", group="cowrie")
            except Exception:
                pass
    except Exception as exc:
        print(f"[plant] chown skipped: {exc}", flush=True)

    # Remove the staging directory (content already copied into honeyfs).
    shutil.rmtree(STAGE, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
