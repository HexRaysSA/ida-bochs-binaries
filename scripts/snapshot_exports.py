#!/usr/bin/env python3
"""Snapshot DLL exports from Wine .spec files into data/stubs/exports.json.

Each export keeps its ordinal: programs import many system DLL functions by
ordinal (oleaut32, comctl32, wsock32, shell32, shlwapi...), so a stub with
renumbered exports binds them to the wrong functions. Ordinals are assigned
like winebuild does: explicit ordinals are kept, and "@" entries take the free
ordinals from the lowest one up, in declaration order. Entries marked
-noname are exported by ordinal only, and an entry implemented by another
DLL ("NTDLL.RtlAllocateHeap") records that forward target. The exports
of the x86 (PE32) and x64 (PE32+) builds are snapshotted separately, as
-arch flags make them differ.

Usage:
  snapshot_exports.py WINE_SRC [--ref wine-9.0] [--dlls ntdll kernel32 ...]

With --ref, the .spec files are read from that git revision of WINE_SRC
(no checkout needed). Without --dlls, the DLLs already in exports.json are
snapshotted again.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

EXPORTS_JSON = Path(__file__).resolve().parent.parent / "data" / "stubs" / "exports.json"

# The -arch names that select the entries winebuild builds for each stub set
ARCH_NAMES = {
    "x86": {"i386", "win32"},
    "x64": {"x86_64", "win64"},
}


def read_spec(wine_src: Path, ref: str | None, dll: str) -> str:
    rel = f"dlls/{dll}/{dll}.spec"
    if ref is None:
        return (wine_src / rel).read_text()
    return subprocess.run(
        ["git", "-C", str(wine_src), "show", f"{ref}:{rel}"],
        check=True, capture_output=True, text=True,
    ).stdout


def arch_matches(arch_flag: str, arch_names: set[str]) -> bool:
    tokens = arch_flag.split(",")
    positive = [t for t in tokens if not t.startswith("!")]
    negative = [t[1:] for t in tokens if t.startswith("!")]
    if any(t in arch_names for t in negative):
        return False
    return not positive or any(t in arch_names for t in positive)


# name, optional "(args)", optional implementation ("Func" or "DLL.Func")
DECL_RE = re.compile(r"(?P<name>[^\s(]+)(?:\s*\([^)]*\))?(?:\s+(?P<impl>\S+))?")


def parse_spec(text: str, arch_names: set[str]) -> list[dict]:
    """Return the exports in declaration order, "ordinal" is None for "@"."""
    entries = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        tokens = line.split(None, 2)
        if len(tokens) < 3:
            continue
        ordinal, _callconv, rest = tokens
        noname = False
        keep = True
        while rest.startswith("-"):
            flag, _, rest = rest.partition(" ")
            rest = rest.lstrip()
            if flag == "-noname":
                noname = True
            elif flag.startswith("-arch="):
                keep = arch_matches(flag[len("-arch="):], arch_names)
            elif flag == "-i386":  # old spelling of -arch=i386
                keep = arch_matches("i386", arch_names)
        m = DECL_RE.match(rest)
        if not keep or not m:
            continue
        entry = {"ordinal": None if ordinal == "@" else int(ordinal)}
        # "@" as the name declares an export without any name
        if m["name"] != "@":
            entry["name"] = m["name"]
        if noname or m["name"] == "@":
            entry["noname"] = True
        if m["impl"] and "." in m["impl"]:
            entry["forward"] = m["impl"]
        entries.append(entry)
    return entries


def assign_ordinals(entries: list[dict]) -> list[dict]:
    used = {e["ordinal"] for e in entries if e["ordinal"] is not None}
    ordinal = min(used) if used else 1
    for e in entries:
        if e["ordinal"] is None:
            while ordinal in used:
                ordinal += 1
            e["ordinal"] = ordinal
            used.add(ordinal)
    return sorted(entries, key=lambda e: e["ordinal"])


def write_json(db: dict[str, dict[str, list[dict]]]) -> None:
    lines = ["{"]
    for k, (arch, dlls) in enumerate(db.items()):
        lines.append(f"  {json.dumps(arch)}: {{")
        for i, (dll, entries) in enumerate(dlls.items()):
            lines.append(f"    {json.dumps(dll)}: [")
            lines.extend(
                f"      {json.dumps(e)}{',' if j + 1 < len(entries) else ''}"
                for j, e in enumerate(entries)
            )
            lines.append("    ]" + ("," if i + 1 < len(dlls) else ""))
        lines.append("  }" + ("," if k + 1 < len(db) else ""))
    lines.append("}")
    EXPORTS_JSON.write_text("\n".join(lines) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("wine_src", type=Path, help="Wine source tree (a git checkout with --ref)")
    parser.add_argument("--ref", help="git revision to read the .spec files from, e.g. wine-9.0")
    parser.add_argument("--dlls", nargs="+", help="DLL names (default: the ones in exports.json)")
    args = parser.parse_args()

    dlls = args.dlls or list(json.loads(EXPORTS_JSON.read_text())["x86"])
    db = {}
    for arch, arch_names in ARCH_NAMES.items():
        db[arch] = {}
        for dll in dlls:
            spec = read_spec(args.wine_src, args.ref, dll)
            db[arch][dll] = assign_ordinals(parse_spec(spec, arch_names))
            print(f"  {arch} {dll}: {len(db[arch][dll])} exports")
    write_json(db)
    print(f"\nwrote {EXPORTS_JSON}")


if __name__ == "__main__":
    main()
