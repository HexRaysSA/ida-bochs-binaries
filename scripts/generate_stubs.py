#!/usr/bin/env python3
"""Generate minimal PE stub DLLs (32-bit and 64-bit) from a local export snapshot.

Reads exports from data/stubs/exports.json (snapshotted from Wine 9.0 .spec
files by scripts/snapshot_exports.py) and creates tiny DLLs containing only
an export directory. IDA's Bochs PE mode reads only the export table from
each DLL — no actual code is needed.

Every export keeps its ordinal, and -noname exports are exported by ordinal
only: programs import many system DLL functions by ordinal, so renumbered
exports would bind them to the wrong functions. Exports that Windows forwards
to another stubbed DLL (kernel32.HeapAlloc -> NTDLL.RtlAllocateHeap) stay
forwarders, so the Bochs API scripts of the target DLL handle them; forwards
to DLLs without a stub become plain exports.

Each DLL gets a unique preferred image base to avoid collisions when IDA's
PE-mode image builder lays out the Bochs disk image.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

EXPORTS_JSON = Path(__file__).resolve().parent.parent / "data" / "stubs" / "exports.json"
OUTPUT_DIR_32 = Path(__file__).resolve().parent.parent / "data" / "stubs" / "windows"
OUTPUT_DIR_64 = Path(__file__).resolve().parent.parent / "data" / "stubs" / "windows64"

DLL_IMAGE_BASE_START_32 = 0x60000000
DLL_IMAGE_BASE_START_64 = 0x180000000
DLL_IMAGE_BASE_STRIDE = 0x01000000

FILE_ALIGNMENT = 0x200
SECTION_ALIGNMENT = 0x1000
HEADERS_SIZE = 0x200
TEXT_RVA = SECTION_ALIGNMENT
TEXT_SIZE = SECTION_ALIGNMENT  # one RET per byte, exports point into it
EDATA_RVA = 2 * SECTION_ALIGNMENT


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _stub_forward(entry: dict, stub_dlls: set[str]) -> str | None:
    """The forward target of entry, if it is kept in the stub."""
    forward = entry.get("forward")
    if forward is None or forward.split(".", 1)[0].lower() not in stub_dlls:
        return None
    return forward


def _build_edata(dll_filename: str, entries: list[dict], stub_dlls: set[str]) -> bytes:
    """Build the export directory of the entries of exports.json."""
    base = min(e["ordinal"] for e in entries)
    nfuncs = max(e["ordinal"] for e in entries) - base + 1
    named = sorted(
        (e["name"].encode(), e["ordinal"]) for e in entries if not e.get("noname")
    )

    eat_off = 40
    names_off = eat_off + 4 * nfuncs
    ords_off = names_off + 4 * len(named)
    strings_off = ords_off + 2 * len(named)

    strings = bytearray(dll_filename.encode() + b"\0")
    name_rvas = []
    for name, _ in named:
        name_rvas.append(EDATA_RVA + strings_off + len(strings))
        strings += name + b"\0"

    eat = [0] * nfuncs
    for i, e in enumerate(entries):
        forward = _stub_forward(e, stub_dlls)
        if forward is None:
            eat[e["ordinal"] - base] = TEXT_RVA + (i % TEXT_SIZE)
        else:
            # a forwarder points at "DLL.Func" inside the export directory
            eat[e["ordinal"] - base] = EDATA_RVA + strings_off + len(strings)
            strings += forward.encode() + b"\0"

    edata = struct.pack(
        "<IIHHIIIIIII",
        0, 0, 0, 0,
        EDATA_RVA + strings_off,  # Name
        base,
        nfuncs,
        len(named),
        EDATA_RVA + eat_off,      # AddressOfFunctions
        EDATA_RVA + names_off,    # AddressOfNames
        EDATA_RVA + ords_off,     # AddressOfNameOrdinals
    )
    edata += struct.pack(f"<{nfuncs}I", *eat)
    edata += struct.pack(f"<{len(named)}I", *name_rvas)
    edata += struct.pack(f"<{len(named)}H", *[o - base for _, o in named])
    edata += strings
    return bytes(edata)


def _build_pe(image_base: int, edata: bytes, *, pe64: bool = False) -> bytes:
    text_raw = HEADERS_SIZE
    text_file_size = _align(TEXT_SIZE, FILE_ALIGNMENT)
    edata_raw = text_raw + text_file_size
    edata_file_size = _align(len(edata), FILE_ALIGNMENT)
    image_size = EDATA_RVA + _align(len(edata), SECTION_ALIGNMENT)

    pe = bytearray(edata_raw + edata_file_size)

    pe[0:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, 0x40)

    pe_off = 0x40
    pe[pe_off:pe_off + 4] = b"PE\x00\x00"

    # PE32+ grows the image base and the stack/heap sizes to 64 bits
    opt_hdr_size = 0xF0 if pe64 else 0xE0
    coff_off = pe_off + 4
    struct.pack_into("<H", pe, coff_off + 0, 0x8664 if pe64 else 0x14C)
    struct.pack_into("<H", pe, coff_off + 2, 2)
    struct.pack_into("<H", pe, coff_off + 16, opt_hdr_size)
    struct.pack_into("<H", pe, coff_off + 18, 0x2022 if pe64 else 0x2102)

    opt_off = coff_off + 20
    struct.pack_into("<H", pe, opt_off + 0, 0x20B if pe64 else 0x10B)
    struct.pack_into("<I", pe, opt_off + 4, text_file_size)
    struct.pack_into("<I", pe, opt_off + 8, edata_file_size)
    struct.pack_into("<I", pe, opt_off + 16, TEXT_RVA)
    struct.pack_into("<I", pe, opt_off + 20, TEXT_RVA)
    if pe64:
        struct.pack_into("<Q", pe, opt_off + 24, image_base)
    else:
        struct.pack_into("<I", pe, opt_off + 24, EDATA_RVA)
        struct.pack_into("<I", pe, opt_off + 28, image_base)
    struct.pack_into("<I", pe, opt_off + 32, SECTION_ALIGNMENT)
    struct.pack_into("<I", pe, opt_off + 36, FILE_ALIGNMENT)
    struct.pack_into("<H", pe, opt_off + 40, 6)
    struct.pack_into("<I", pe, opt_off + 56, image_size)
    struct.pack_into("<I", pe, opt_off + 60, HEADERS_SIZE)
    struct.pack_into("<H", pe, opt_off + 68, 3)
    size_fmt = "<QQQQ" if pe64 else "<IIII"
    struct.pack_into(size_fmt, pe, opt_off + 72, 0x100000, 0x1000, 0x100000, 0x1000)
    dirs_off = opt_off + (112 if pe64 else 96)
    struct.pack_into("<I", pe, dirs_off - 4, 16)
    struct.pack_into("<II", pe, dirs_off, EDATA_RVA, len(edata))

    sec_off = opt_off + opt_hdr_size
    pe[sec_off:sec_off + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", pe, sec_off + 8, TEXT_SIZE, TEXT_RVA, text_file_size, text_raw)
    struct.pack_into("<I", pe, sec_off + 36, 0x60000020)

    sec_off += 40
    pe[sec_off:sec_off + 8] = b".edata\x00\x00"
    struct.pack_into("<IIII", pe, sec_off + 8, len(edata), EDATA_RVA, edata_file_size, edata_raw)
    struct.pack_into("<I", pe, sec_off + 36, 0x40000040)

    pe[text_raw:text_raw + TEXT_SIZE] = b"\xC3" * TEXT_SIZE
    pe[edata_raw:edata_raw + len(edata)] = edata
    return bytes(pe)


def read_stub(pe: bytes) -> dict:
    """Parse a stub: its headers and the (ordinal, name, forward) of its exports."""
    opt_off = 0x40 + 4 + 20
    machine, nsections = struct.unpack_from("<HH", pe, 0x44)
    characteristics, = struct.unpack_from("<H", pe, 0x44 + 18)
    pe64 = struct.unpack_from("<H", pe, opt_off)[0] == 0x20B
    if pe64:
        image_base, = struct.unpack_from("<Q", pe, opt_off + 24)
    else:
        image_base, = struct.unpack_from("<I", pe, opt_off + 28)
    edata_rva, edata_size = struct.unpack_from("<II", pe, opt_off + (112 if pe64 else 96))
    opt_hdr_size, = struct.unpack_from("<H", pe, 0x44 + 16)
    sec_off = opt_off + opt_hdr_size
    sections = [
        pe[sec_off + 40 * i:sec_off + 40 * i + 8].rstrip(b"\0").decode()
        for i in range(nsections)
    ]
    raw = pe[HEADERS_SIZE + _align(TEXT_SIZE, FILE_ALIGNMENT):]

    def at(rva: int) -> int:
        return rva - edata_rva

    def string(rva: int) -> str:
        return raw[at(rva):raw.index(b"\0", at(rva))].decode()

    (_, _, _, _, name_rva, base, nfuncs, nnames,
     eat_rva, names_rva, ords_rva) = struct.unpack_from("<IIHHIIIIIII", raw, 0)
    eat = struct.unpack_from(f"<{nfuncs}I", raw, at(eat_rva))
    names = struct.unpack_from(f"<{nnames}I", raw, at(names_rva))
    ords = struct.unpack_from(f"<{nnames}H", raw, at(ords_rva))
    by_index = {index: string(rva) for rva, index in zip(names, ords)}
    exports = set()
    for i, rva in enumerate(eat):
        if rva == 0:
            continue
        is_forward = edata_rva <= rva < edata_rva + edata_size
        exports.add((base + i, by_index.get(i), string(rva) if is_forward else None))
    return {
        "pe64": pe64,
        "machine": machine,
        "characteristics": characteristics,
        "image_base": image_base,
        "sections": sections,
        "dll_name": string(name_rva),
        "names": [string(rva) for rva in names],
        "exports": exports,
    }


def build_stub_dll(
    dll_filename: str,
    entries: list[dict],
    output_path: Path,
    image_base: int,
    *,
    pe64: bool = False,
    stub_dlls: set[str] = frozenset(),
) -> None:
    edata = _build_edata(dll_filename, entries, stub_dlls)
    output_path.write_bytes(_build_pe(image_base, edata, pe64=pe64))


def _generate_stubs(
    exports_db: dict[str, list[dict]],
    output_dir: Path,
    base_start: int,
    *,
    pe64: bool = False,
) -> list[str]:
    label = "PE32+" if pe64 else "PE32"
    stub_dlls = {name.lower() for name in exports_db}
    output_dir.mkdir(parents=True, exist_ok=True)
    for dll_name in exports_db:
        (output_dir / f"{dll_name}.dll").unlink(missing_ok=True)

    failures: list[str] = []

    for i, (dll_name, entries) in enumerate(exports_db.items()):
        dll_filename = f"{dll_name}.dll"
        out_path = output_dir / dll_filename
        image_base = base_start + i * DLL_IMAGE_BASE_STRIDE

        try:
            build_stub_dll(
                dll_filename, entries, out_path, image_base,
                pe64=pe64, stub_dlls=stub_dlls,
            )

            parsed = read_stub(out_path.read_bytes())
            if parsed["pe64"] != pe64:
                raise RuntimeError("wrong PE format")
            if parsed["image_base"] != image_base:
                raise RuntimeError(
                    f"image base 0x{parsed['image_base']:X}, expected 0x{image_base:X}"
                )
            expected = {
                (e["ordinal"],
                 None if e.get("noname") else e["name"],
                 _stub_forward(e, stub_dlls))
                for e in entries
            }
            if parsed["exports"] != expected:
                raise RuntimeError(
                    f"{len(parsed['exports'] ^ expected)} exports differ from the snapshot"
                )

            print(f"  [{label}] {dll_name}: {len(expected)} exports, "
                  f"{out_path.stat().st_size} bytes")
        except Exception as e:
            out_path.unlink(missing_ok=True)
            failures.append(f"{dll_filename}: {e}")
            print(f"  [{label}] {dll_name}: ERROR: {e}")

    return failures


def main() -> None:
    exports_db: dict[str, dict[str, list[dict]]] = json.loads(EXPORTS_JSON.read_text())

    failures: list[str] = []
    failures += _generate_stubs(exports_db["x86"], OUTPUT_DIR_32, DLL_IMAGE_BASE_START_32)
    failures += _generate_stubs(
        exports_db["x64"], OUTPUT_DIR_64, DLL_IMAGE_BASE_START_64, pe64=True,
    )

    missing_32 = [n for n in exports_db["x86"] if not (OUTPUT_DIR_32 / f"{n}.dll").is_file()]
    missing_64 = [n for n in exports_db["x64"] if not (OUTPUT_DIR_64 / f"{n}.dll").is_file()]

    if failures or missing_32 or missing_64:
        print("\nfailed")
        for f in failures:
            print(f"  {f}")
        raise SystemExit(1)

    print(f"\n{len(exports_db['x86'])} stubs generated (PE32 + PE32+)")


if __name__ == "__main__":
    main()
