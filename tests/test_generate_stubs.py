"""Tests for PE32 and PE32+ stub DLL generation."""

from __future__ import annotations

import sys
from pathlib import Path

import lief
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from generate_stubs import (
    DLL_IMAGE_BASE_START_32,
    DLL_IMAGE_BASE_START_64,
    DLL_IMAGE_BASE_STRIDE,
    _create_skeleton_pe,
    build_stub_dll,
)

SAMPLE_EXPORTS = ["CreateFileA", "CreateFileW", "ReadFile", "WriteFile", "CloseHandle"]


def test_pe32_magic():
    raw = _create_skeleton_pe(0x10000000)
    pe = lief.PE.parse(raw)
    assert pe is not None
    assert pe.optional_header.magic == lief.PE.PE_TYPE.PE32


def test_pe64_magic():
    raw = _create_skeleton_pe(0x180000000, pe64=True)
    pe = lief.PE.parse(raw)
    assert pe is not None
    assert pe.optional_header.magic == lief.PE.PE_TYPE.PE32_PLUS


def test_pe32_machine():
    raw = _create_skeleton_pe(0x10000000)
    pe = lief.PE.parse(raw)
    assert pe.header.machine == lief.PE.Header.MACHINE_TYPES.I386


def test_pe64_machine():
    raw = _create_skeleton_pe(0x180000000, pe64=True)
    pe = lief.PE.parse(raw)
    assert pe.header.machine == lief.PE.Header.MACHINE_TYPES.AMD64


def test_pe32_image_base():
    base = 0x60000000
    raw = _create_skeleton_pe(base)
    pe = lief.PE.parse(raw)
    assert pe.optional_header.imagebase == base


def test_pe64_image_base():
    base = 0x180000000
    raw = _create_skeleton_pe(base, pe64=True)
    pe = lief.PE.parse(raw)
    assert pe.optional_header.imagebase == base


def test_pe64_image_base_above_4gb():
    base = 0x7FF800000000
    raw = _create_skeleton_pe(base, pe64=True)
    pe = lief.PE.parse(raw)
    assert pe.optional_header.imagebase == base


def test_pe32_is_dll():
    raw = _create_skeleton_pe(0x10000000)
    pe = lief.PE.parse(raw)
    assert pe.header.has_characteristic(lief.PE.Header.CHARACTERISTICS.DLL)


def test_pe64_is_dll():
    raw = _create_skeleton_pe(0x180000000, pe64=True)
    pe = lief.PE.parse(raw)
    assert pe.header.has_characteristic(lief.PE.Header.CHARACTERISTICS.DLL)


def test_pe64_large_address_aware():
    raw = _create_skeleton_pe(0x180000000, pe64=True)
    pe = lief.PE.parse(raw)
    assert pe.header.has_characteristic(
        lief.PE.Header.CHARACTERISTICS.LARGE_ADDRESS_AWARE
    )


def test_pe32_has_text_section():
    raw = _create_skeleton_pe(0x10000000)
    pe = lief.PE.parse(raw)
    sections = [s.name for s in pe.sections]
    assert ".text" in sections


def test_pe64_has_text_section():
    raw = _create_skeleton_pe(0x180000000, pe64=True)
    pe = lief.PE.parse(raw)
    sections = [s.name for s in pe.sections]
    assert ".text" in sections


def test_pe32_stub_has_exports(tmp_path):
    out = tmp_path / "test32.dll"
    build_stub_dll("test32.dll", SAMPLE_EXPORTS, out, 0x60000000)
    pe = lief.PE.parse(str(out))
    assert pe is not None
    exp = pe.get_export()
    assert exp is not None
    names = [e.name for e in exp.entries]
    for name in SAMPLE_EXPORTS:
        assert name in names


def test_pe64_stub_has_exports(tmp_path):
    out = tmp_path / "test64.dll"
    build_stub_dll("test64.dll", SAMPLE_EXPORTS, out, 0x180000000, pe64=True)
    pe = lief.PE.parse(str(out))
    assert pe is not None
    exp = pe.get_export()
    assert exp is not None
    names = [e.name for e in exp.entries]
    for name in SAMPLE_EXPORTS:
        assert name in names


def test_pe64_stub_is_pe32_plus(tmp_path):
    out = tmp_path / "test64.dll"
    build_stub_dll("test64.dll", SAMPLE_EXPORTS, out, 0x180000000, pe64=True)
    pe = lief.PE.parse(str(out))
    assert pe.optional_header.magic == lief.PE.PE_TYPE.PE32_PLUS
    assert pe.header.machine == lief.PE.Header.MACHINE_TYPES.AMD64


def test_pe32_stub_preserves_image_base(tmp_path):
    base = 0x61000000
    out = tmp_path / "test.dll"
    build_stub_dll("test.dll", SAMPLE_EXPORTS, out, base)
    pe = lief.PE.parse(str(out))
    assert pe.optional_header.imagebase == base


def test_pe64_stub_preserves_image_base(tmp_path):
    base = 0x181000000
    out = tmp_path / "test.dll"
    build_stub_dll("test.dll", SAMPLE_EXPORTS, out, base, pe64=True)
    pe = lief.PE.parse(str(out))
    assert pe.optional_header.imagebase == base


def test_export_count_matches(tmp_path):
    out = tmp_path / "test.dll"
    build_stub_dll("test.dll", SAMPLE_EXPORTS, out, 0x60000000)
    pe = lief.PE.parse(str(out))
    assert len(list(pe.get_export().entries)) == len(SAMPLE_EXPORTS)


def test_pe64_export_count_matches(tmp_path):
    out = tmp_path / "test.dll"
    build_stub_dll("test.dll", SAMPLE_EXPORTS, out, 0x180000000, pe64=True)
    pe = lief.PE.parse(str(out))
    assert len(list(pe.get_export().entries)) == len(SAMPLE_EXPORTS)


def test_export_name_matches_dll(tmp_path):
    out = tmp_path / "kernel32.dll"
    build_stub_dll("kernel32.dll", SAMPLE_EXPORTS, out, 0x60000000)
    pe = lief.PE.parse(str(out))
    assert pe.get_export().name == "kernel32.dll"


def test_unique_image_bases_no_collision(tmp_path):
    dll_names = ["ntdll", "kernel32", "user32"]
    bases_32 = []
    bases_64 = []
    for i, name in enumerate(dll_names):
        b32 = DLL_IMAGE_BASE_START_32 + i * DLL_IMAGE_BASE_STRIDE
        b64 = DLL_IMAGE_BASE_START_64 + i * DLL_IMAGE_BASE_STRIDE
        out32 = tmp_path / f"{name}_32.dll"
        out64 = tmp_path / f"{name}_64.dll"
        build_stub_dll(f"{name}.dll", ["Foo"], out32, b32)
        build_stub_dll(f"{name}.dll", ["Foo"], out64, b64, pe64=True)
        bases_32.append(lief.PE.parse(str(out32)).optional_header.imagebase)
        bases_64.append(lief.PE.parse(str(out64)).optional_header.imagebase)

    assert len(set(bases_32)) == len(dll_names)
    assert len(set(bases_64)) == len(dll_names)
    assert not set(bases_32) & set(bases_64)
