#!/usr/bin/env python3
"""Snapshot the exports of real Windows 11 DLLs into data/stubs/exports.json.

Each export keeps its real ordinal, ordinal-only exports stay without a name,
and forwarders are kept when they point to another stubbed DLL: programs
import many system DLL functions by ordinal (oleaut32, comctl32, wsock32,
shell32...), and Bochs implements some APIs only in the forward target
(kernel32.HeapAlloc -> NTDLL.RtlAllocateHeap). Forwards to API sets, to
kernelbase or to DLLs without a stub become plain exports, so the Bochs API
scripts of the DLL that declares them still apply.

The DLLs are pinned in data/stubs/sources.json: the x64 DLLs of System32 and
the x86 DLLs of SysWOW64 of the Windows 11 24H2 release, plus the v6
comctl32 of WinSxS, whose exports go first. They are downloaded from the
Microsoft symbol server and checked against their SHA-256; only the export
names and ordinals are committed. --pin fills sources.json from Winbindex.

Usage:
  snapshot_exports.py [--pin] [--dir WINDIR ...] [--cache DIR]
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import struct
import time
import urllib.error
import urllib.request
from pathlib import Path

STUBS_DIR = Path(__file__).resolve().parent.parent / "data" / "stubs"
EXPORTS_JSON = STUBS_DIR / "exports.json"
SOURCES_JSON = STUBS_DIR / "sources.json"
DEFAULT_CACHE = Path(__file__).resolve().parent.parent / ".cache" / "windows-dlls"

WINDOWS_VERSION = "11-24H2"
WINBINDEX_URL = "https://winbindex.m417z.com/data/by_filename_compressed/{}.json.gz"
MSDL_URL = "https://msdl.microsoft.com/download/symbols/{0}/{1:08X}{2:x}/{0}"
USER_AGENT = "Microsoft-Symbol-Server/10.0.0.0"

# (machine, install directory) of the DLLs of each stub set
ARCHES = {
    "x86": (0x14C, "windows\\syswow64\\"),
    "x64": (0x8664, "windows\\system32\\"),
}
WINSXS_COMCTL32 = "Microsoft.Windows.Common-Controls"


def _download(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    for attempt in range(8):
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            # the symbol server answers 503 when busy
            if e.code < 500 or attempt == 7:
                raise
            time.sleep(2 ** attempt)
    raise AssertionError


def _source(entry: dict, file: str, path: str) -> dict:
    fi = entry["fileInfo"]
    return {
        "file": file,
        "path": path,
        "version": fi["version"].split()[0],
        "timestamp": fi["timestamp"],
        "size_of_image": fi["virtualSize"],
        "sha256": fi["sha256"],
    }


def pin_dll(dll: str, cache: Path) -> dict[str, list[dict]]:
    """The Windows 11 files of dll for each architecture, from Winbindex."""
    file = f"{dll}.dll"
    path = cache / "winbindex" / f"{file}.json.gz"
    if not path.is_file():
        try:
            data = _download(WINBINDEX_URL.format(file))
        except urllib.error.HTTPError as e:
            # not a Windows file
            if e.code != 404:
                raise
            data = gzip.compress(b"{}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    db = json.loads(gzip.decompress(path.read_bytes()))

    pinned: dict[str, list[dict]] = {}
    for arch, (machine, install_dir) in ARCHES.items():
        sources = []
        winsxs = []
        for entry in db.values():
            fi = entry.get("fileInfo", {})
            if fi.get("machineType") != machine or "virtualSize" not in fi:
                continue
            updates = entry.get("windowsVersions", {}).get(WINDOWS_VERSION, {})
            for sp in updates.get("BASE", {}).get("sourcePaths", []):
                if sp.lower() == install_dir + file:
                    sources.append(_source(entry, file, sp))
            if dll == "comctl32":
                for kb, update in updates.items():
                    for asm in update.get("assemblies", {}).values():
                        ident = asm["assemblyIdentity"]
                        if ident.get("name") == WINSXS_COMCTL32 and fi["version"].startswith("6."):
                            version = tuple(int(x) for x in ident["version"].split("."))
                            winsxs.append((version, _source(entry, file, f"WinSxS ({kb})")))
        if winsxs:
            # the v6 build of the first update that ships it
            sources.insert(0, min(winsxs, key=lambda s: s[0])[1])
        if sources:
            pinned[arch] = sources
    return pinned


def fetch(src: dict, cache: Path, local_dirs: list[Path]) -> bytes:
    """The bytes of a pinned DLL: from the cache, a local copy or the symbol server."""
    cached = cache / f"{src['sha256']}.dll"
    if cached.is_file():
        return cached.read_bytes()
    data = None
    for d in local_dirs:
        p = d / src["file"]
        if p.is_file() and hashlib.sha256(p.read_bytes()).hexdigest() == src["sha256"]:
            data = p.read_bytes()
            break
    if data is None:
        data = _download(MSDL_URL.format(src["file"], src["timestamp"], src["size_of_image"]))
    if hashlib.sha256(data).hexdigest() != src["sha256"]:
        # builds with the same timestamp and image size share a symbol
        # server key, the server returns one of them
        pe_off, = struct.unpack_from("<I", data, 0x3C)
        timestamp, = struct.unpack_from("<I", data, pe_off + 8)
        size_of_image, = struct.unpack_from("<I", data, pe_off + 24 + 56)
        if (timestamp, size_of_image) != (src["timestamp"], src["size_of_image"]):
            raise RuntimeError(f"{src['file']} {src['version']}: SHA-256 mismatch")
        print(f"  warning: {src['file']} {src['version']}: another build with the same key")
    cache.mkdir(parents=True, exist_ok=True)
    cached.write_bytes(data)
    return data


def read_exports(pe: bytes) -> tuple[int, list[dict]]:
    """The machine of a PE file and its exports as exports.json entries."""
    pe_off, = struct.unpack_from("<I", pe, 0x3C)
    if pe[pe_off:pe_off + 4] != b"PE\0\0":
        raise ValueError("not a PE file")
    machine, nsections = struct.unpack_from("<HH", pe, pe_off + 4)
    opt_hdr_size, = struct.unpack_from("<H", pe, pe_off + 20)
    opt_off = pe_off + 24
    pe64 = struct.unpack_from("<H", pe, opt_off)[0] == 0x20B
    edata_rva, edata_size = struct.unpack_from("<II", pe, opt_off + (112 if pe64 else 96))
    sections = [
        struct.unpack_from("<IIII", pe, opt_off + opt_hdr_size + 40 * i + 8)
        for i in range(nsections)
    ]

    def offset(rva: int) -> int:
        for vsize, va, rawsize, rawptr in sections:
            if va <= rva < va + max(vsize, rawsize):
                return rva - va + rawptr
        raise ValueError(f"RVA {rva:#x} outside the sections")

    def string(rva: int) -> str:
        off = offset(rva)
        return pe[off:pe.index(b"\0", off)].decode("ascii")

    if edata_rva == 0:
        return machine, []
    (_, _, _, _, _, base, nfuncs, nnames,
     eat_rva, names_rva, ords_rva) = struct.unpack_from("<IIHHIIIIIII", pe, offset(edata_rva))
    eat = struct.unpack_from(f"<{nfuncs}I", pe, offset(eat_rva)) if nfuncs else ()
    names = struct.unpack_from(f"<{nnames}I", pe, offset(names_rva)) if nnames else ()
    ords = struct.unpack_from(f"<{nnames}H", pe, offset(ords_rva)) if nnames else ()
    by_index: dict[int, str] = {}
    for rva, index in zip(names, ords):
        by_index.setdefault(index, string(rva))

    entries = []
    for i, rva in enumerate(eat):
        if rva == 0:
            continue
        entry: dict = {"ordinal": base + i}
        if i in by_index:
            entry["name"] = by_index[i]
        else:
            entry["noname"] = True
        if edata_rva <= rva < edata_rva + edata_size:
            entry["forward"] = string(rva)
        entries.append(entry)
    return machine, entries


def keep_forward(forward: str, stub_dlls: set[str]) -> bool:
    target = forward.split(".", 1)[0].lower()
    return target in stub_dlls and target != "kernelbase"


def merge_exports(sources: list[list[dict]], stub_dlls: set[str]) -> list[dict]:
    """Merge the exports of the files of one DLL, the first file wins."""
    merged: dict[int, dict] = {}
    names: set[str] = set()
    for entries in sources:
        for e in entries:
            if e["ordinal"] in merged or e.get("name") in names:
                continue
            e = dict(e)
            if "forward" in e and not keep_forward(e["forward"], stub_dlls):
                del e["forward"]
            merged[e["ordinal"]] = e
            if "name" in e:
                names.add(e["name"])
    return [merged[o] for o in sorted(merged)]


def write_json(path: Path, db: dict) -> None:
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
    path.write_text("\n".join(lines) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--pin", action="store_true",
                        help="refill sources.json from Winbindex first")
    parser.add_argument("--dir", type=Path, action="append", default=[],
                        help="local Windows directory to take matching DLLs from")
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE,
                        help=f"download cache (default: {DEFAULT_CACHE})")
    args = parser.parse_args()

    exports_db = json.loads(EXPORTS_JSON.read_text())
    dlls = list(dict.fromkeys([*exports_db["x86"], *exports_db["x64"]]))

    if args.pin:
        pinned = {arch: {} for arch in ARCHES}
        for dll in dlls:
            for arch, sources in pin_dll(dll, args.cache).items():
                pinned[arch][dll] = sources
        sources_db = {"windows": WINDOWS_VERSION, **pinned}
        SOURCES_JSON.write_text(json.dumps(sources_db, indent=2) + "\n")
        print(f"wrote {SOURCES_JSON}")
    sources_db = json.loads(SOURCES_JSON.read_text())

    db: dict[str, dict[str, list[dict]]] = {}
    for arch, (machine, _) in ARCHES.items():
        stub_dlls = set(sources_db[arch])
        db[arch] = {}
        for dll in dlls:
            if dll not in sources_db[arch]:
                # redistributables (msvcr*, vcruntime140...) are not part of
                # Windows, keep their previous exports
                if dll in exports_db.get(arch, {}):
                    db[arch][dll] = exports_db[arch][dll]
                    print(f"  {arch} {dll}: not in Windows {sources_db['windows']}, kept")
                else:
                    print(f"  {arch} {dll}: not in Windows {sources_db['windows']}, no stub")
                continue
            files = []
            for src in sources_db[arch][dll]:
                pe_machine, entries = read_exports(fetch(src, args.cache, args.dir))
                if pe_machine != machine:
                    raise SystemExit(f"{arch} {dll} {src['version']}: wrong machine {pe_machine:#x}")
                files.append(entries)
            db[arch][dll] = merge_exports(files, stub_dlls)
            versions = " + ".join(s["version"] for s in sources_db[arch][dll])
            print(f"  {arch} {dll}: {len(db[arch][dll])} exports ({versions})")
    write_json(EXPORTS_JSON, db)
    print(f"\nwrote {EXPORTS_JSON}")


if __name__ == "__main__":
    main()
