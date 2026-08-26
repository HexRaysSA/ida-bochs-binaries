#!/usr/bin/env python3
"""Generate minimal PE stub DLLs (32-bit and 64-bit) from a local export snapshot.

Reads export names from data/stubs/exports.json (snapshotted from Wine
.spec files) and creates tiny DLLs containing only an export directory.
IDA's Bochs PE mode reads only the export table from each DLL — no actual
code is needed.

Each DLL gets a unique preferred image base to avoid collisions when IDA's
PE-mode image builder lays out the Bochs disk image.
"""

from __future__ import annotations

import json
import struct
import tempfile
from pathlib import Path

import lief

EXPORTS_JSON = Path(__file__).resolve().parent.parent / "data" / "stubs" / "exports.json"
OUTPUT_DIR_32 = Path(__file__).resolve().parent.parent / "data" / "stubs" / "windows"
OUTPUT_DIR_64 = Path(__file__).resolve().parent.parent / "data" / "stubs" / "windows64"

DLL_IMAGE_BASE_START_32 = 0x60000000
DLL_IMAGE_BASE_START_64 = 0x180000000
DLL_IMAGE_BASE_STRIDE = 0x01000000


def _create_skeleton_pe(image_base: int, *, pe64: bool = False) -> bytes:
    FILE_ALIGNMENT = 0x200
    SECTION_ALIGNMENT = 0x1000

    text_rva = SECTION_ALIGNMENT
    text_raw = b"\xC3" * SECTION_ALIGNMENT
    text_file_size = (len(text_raw) + FILE_ALIGNMENT - 1) & ~(FILE_ALIGNMENT - 1)

    opt_hdr_size = 0xF0 if pe64 else 0xE0
    headers_size = 0x200
    text_file_offset = headers_size
    total_file_size = text_file_offset + text_file_size
    image_size = text_rva + SECTION_ALIGNMENT

    pe = bytearray(total_file_size)

    pe[0:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, 0x40)

    pe_off = 0x40
    pe[pe_off:pe_off + 4] = b"PE\x00\x00"

    coff_off = pe_off + 4
    struct.pack_into("<H", pe, coff_off + 0, 0x8664 if pe64 else 0x14C)
    struct.pack_into("<H", pe, coff_off + 2, 1)
    struct.pack_into("<H", pe, coff_off + 16, opt_hdr_size)
    struct.pack_into("<H", pe, coff_off + 18, 0x2022 if pe64 else 0x2102)

    opt_off = coff_off + 20
    struct.pack_into("<H", pe, opt_off + 0, 0x20B if pe64 else 0x10B)
    struct.pack_into("<I", pe, opt_off + 16, text_rva)
    struct.pack_into("<I", pe, opt_off + 20, text_rva)

    if pe64:
        struct.pack_into("<Q", pe, opt_off + 24, image_base)
    else:
        struct.pack_into("<I", pe, opt_off + 28, image_base)

    struct.pack_into("<I", pe, opt_off + 32, SECTION_ALIGNMENT)
    struct.pack_into("<I", pe, opt_off + 36, FILE_ALIGNMENT)
    struct.pack_into("<H", pe, opt_off + 40, 6)
    struct.pack_into("<I", pe, opt_off + 56, image_size)
    struct.pack_into("<I", pe, opt_off + 60, headers_size)
    struct.pack_into("<H", pe, opt_off + 68, 3)

    if pe64:
        struct.pack_into("<Q", pe, opt_off + 72, 0x100000)
        struct.pack_into("<Q", pe, opt_off + 80, 0x1000)
        struct.pack_into("<Q", pe, opt_off + 88, 0x100000)
        struct.pack_into("<Q", pe, opt_off + 96, 0x1000)
        struct.pack_into("<I", pe, opt_off + 108, 16)
    else:
        struct.pack_into("<I", pe, opt_off + 72, 0x100000)
        struct.pack_into("<I", pe, opt_off + 76, 0x1000)
        struct.pack_into("<I", pe, opt_off + 80, 0x100000)
        struct.pack_into("<I", pe, opt_off + 84, 0x1000)
        struct.pack_into("<I", pe, opt_off + 92, 16)

    sec_off = opt_off + opt_hdr_size
    pe[sec_off:sec_off + 8] = b".text\x00\x00\x00"
    struct.pack_into("<I", pe, sec_off + 8, len(text_raw))
    struct.pack_into("<I", pe, sec_off + 12, text_rva)
    struct.pack_into("<I", pe, sec_off + 16, text_file_size)
    struct.pack_into("<I", pe, sec_off + 20, text_file_offset)
    struct.pack_into("<I", pe, sec_off + 36, 0x60000020)

    pe[text_file_offset:text_file_offset + len(text_raw)] = text_raw

    return bytes(pe)


def build_stub_dll(
    dll_filename: str,
    export_names: list[str],
    output_path: Path,
    image_base: int,
    *,
    pe64: bool = False,
) -> None:
    with tempfile.NamedTemporaryFile(suffix=".dll", delete=False) as tmp:
        tmp.write(_create_skeleton_pe(image_base, pe64=pe64))
        tmp_path = Path(tmp.name)

    try:
        binary = lief.PE.parse(str(tmp_path))
        assert binary is not None, f"failed to parse skeleton PE for {dll_filename}"

        export = lief.PE.Export()
        export.name = dll_filename

        text_rva = 0x1000
        for i, name in enumerate(export_names):
            entry = lief.PE.ExportEntry()
            entry.name = name
            entry.ordinal = i + 1
            entry.address = text_rva + (i % 0x1000)
            export.add_entry(entry)

        binary.set_export(export)

        cfg = lief.PE.Builder.config_t()
        cfg.exports = True

        builder = lief.PE.Builder(binary, cfg)
        builder.build()
        builder.write(str(output_path))
    finally:
        tmp_path.unlink(missing_ok=True)


def _generate_stubs(
    exports_db: dict[str, list[str]],
    output_dir: Path,
    base_start: int,
    *,
    pe64: bool = False,
) -> list[str]:
    label = "PE32+" if pe64 else "PE32"
    output_dir.mkdir(parents=True, exist_ok=True)
    for dll_name in exports_db:
        (output_dir / f"{dll_name}.dll").unlink(missing_ok=True)

    failures: list[str] = []

    for i, (dll_name, export_names) in enumerate(exports_db.items()):
        dll_filename = f"{dll_name}.dll"
        out_path = output_dir / dll_filename
        image_base = base_start + i * DLL_IMAGE_BASE_STRIDE

        try:
            build_stub_dll(
                dll_filename, export_names, out_path, image_base, pe64=pe64,
            )

            parsed = lief.PE.parse(str(out_path))
            if not parsed:
                raise RuntimeError("failed to parse output")
            if parsed.optional_header.imagebase != image_base:
                raise RuntimeError(
                    f"image base 0x{parsed.optional_header.imagebase:X}, "
                    f"expected 0x{image_base:X}"
                )
            exp = parsed.get_export()
            if not exp:
                raise RuntimeError("no exports in output")
            count = len(list(exp.entries))
            if count != len(export_names):
                raise RuntimeError(f"{count} exports, expected {len(export_names)}")

            print(f"  [{label}] {dll_name}: {count} exports, {out_path.stat().st_size} bytes")
        except Exception as e:
            out_path.unlink(missing_ok=True)
            failures.append(f"{dll_filename}: {e}")
            print(f"  [{label}] {dll_name}: ERROR: {e}")

    return failures


def main() -> None:
    exports_db: dict[str, list[str]] = json.loads(EXPORTS_JSON.read_text())

    failures: list[str] = []
    failures += _generate_stubs(exports_db, OUTPUT_DIR_32, DLL_IMAGE_BASE_START_32)
    failures += _generate_stubs(exports_db, OUTPUT_DIR_64, DLL_IMAGE_BASE_START_64, pe64=True)

    missing_32 = [n for n in exports_db if not (OUTPUT_DIR_32 / f"{n}.dll").is_file()]
    missing_64 = [n for n in exports_db if not (OUTPUT_DIR_64 / f"{n}.dll").is_file()]

    if failures or missing_32 or missing_64:
        print("\nfailed")
        for f in failures:
            print(f"  {f}")
        raise SystemExit(1)

    print(f"\n{len(exports_db)} stubs generated (PE32 + PE32+)")


if __name__ == "__main__":
    main()
