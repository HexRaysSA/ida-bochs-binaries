"""Tests for PE32 and PE32+ stub DLL generation."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from generate_stubs import (
    DLL_IMAGE_BASE_START_32,
    DLL_IMAGE_BASE_START_64,
    DLL_IMAGE_BASE_STRIDE,
    build_stub_dll,
    read_stub,
)
from snapshot_exports import ARCH_NAMES, add_extra_exports, assign_ordinals, parse_spec

SAMPLE_EXPORTS = [
    {"ordinal": 1, "name": "CreateFileA"},
    {"ordinal": 2, "name": "CreateFileW"},
    {"ordinal": 3, "name": "ReadFile"},
    {"ordinal": 4, "name": "WriteFile"},
    {"ordinal": 5, "name": "CloseHandle"},
]

IMAGE_FILE_DLL = 0x2000
IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020


def _stub(tmp_path, entries=SAMPLE_EXPORTS, base=0x60000000, *, pe64=False,
          name="test.dll", stub_dlls=frozenset()):
    out = tmp_path / name
    build_stub_dll(name, entries, out, base, pe64=pe64, stub_dlls=stub_dlls)
    return read_stub(out.read_bytes())


@pytest.mark.parametrize("pe64", [False, True])
def test_magic_and_machine(tmp_path, pe64):
    stub = _stub(tmp_path, pe64=pe64)
    assert stub["pe64"] == pe64
    assert stub["machine"] == (0x8664 if pe64 else 0x14C)


@pytest.mark.parametrize("pe64,base", [
    (False, 0x60000000),
    (True, 0x180000000),
    (True, 0x7FF800000000),
])
def test_image_base(tmp_path, pe64, base):
    assert _stub(tmp_path, base=base, pe64=pe64)["image_base"] == base


@pytest.mark.parametrize("pe64", [False, True])
def test_is_dll(tmp_path, pe64):
    assert _stub(tmp_path, pe64=pe64)["characteristics"] & IMAGE_FILE_DLL


def test_pe64_large_address_aware(tmp_path):
    stub = _stub(tmp_path, base=0x180000000, pe64=True)
    assert stub["characteristics"] & IMAGE_FILE_LARGE_ADDRESS_AWARE


@pytest.mark.parametrize("pe64", [False, True])
def test_sections(tmp_path, pe64):
    assert _stub(tmp_path, pe64=pe64)["sections"] == [".text", ".edata"]


@pytest.mark.parametrize("pe64", [False, True])
def test_exports_match(tmp_path, pe64):
    stub = _stub(tmp_path, pe64=pe64)
    assert stub["exports"] == {(e["ordinal"], e["name"], None) for e in SAMPLE_EXPORTS}


def test_export_name_matches_dll(tmp_path):
    assert _stub(tmp_path, name="kernel32.dll")["dll_name"] == "kernel32.dll"


def test_names_are_sorted(tmp_path):
    # the Windows loader binary-searches the name table
    entries = [{"ordinal": i + 1, "name": n} for i, n in enumerate(["b", "A", "a", "_c"])]
    names = _stub(tmp_path, entries)["names"]
    assert names == sorted(names, key=str.encode)


@pytest.mark.parametrize("pe64", [False, True])
def test_ordinals_are_kept(tmp_path, pe64):
    # oleaut32 has no ordinal 1, programs import SysAllocString as #2
    entries = [
        {"ordinal": 2, "name": "SysAllocString"},
        {"ordinal": 9, "name": "VariantClear"},
        {"ordinal": 6, "name": "SysFreeString"},
    ]
    stub = _stub(tmp_path, entries, pe64=pe64)
    assert stub["exports"] == {(2, "SysAllocString", None),
                               (9, "VariantClear", None),
                               (6, "SysFreeString", None)}


def test_noname_is_exported_by_ordinal_only(tmp_path):
    entries = [
        {"ordinal": 410, "name": "SetWindowSubclass"},
        {"ordinal": 17, "name": "InitCommonControls"},
        {"ordinal": 236, "name": "Str_SetPtrW", "noname": True},
    ]
    stub = _stub(tmp_path, entries)
    assert (236, None, None) in stub["exports"]
    assert "Str_SetPtrW" not in stub["names"]


def test_forwarders_to_stubbed_dlls_are_kept(tmp_path):
    entries = [
        {"ordinal": 1, "name": "EncodePointer", "forward": "NTDLL.RtlEncodePointer"},
        {"ordinal": 2, "name": "Foo", "forward": "notstubbed.Foo"},
    ]
    stub = _stub(tmp_path, entries, name="kernel32.dll", stub_dlls={"ntdll", "kernel32"})
    assert stub["exports"] == {(1, "EncodePointer", "NTDLL.RtlEncodePointer"),
                               (2, "Foo", None)}


def test_unique_image_bases_no_collision(tmp_path):
    dll_names = ["ntdll", "kernel32", "user32"]
    entries = [{"ordinal": 1, "name": "Foo"}]
    bases_32 = []
    bases_64 = []
    for i, name in enumerate(dll_names):
        b32 = DLL_IMAGE_BASE_START_32 + i * DLL_IMAGE_BASE_STRIDE
        b64 = DLL_IMAGE_BASE_START_64 + i * DLL_IMAGE_BASE_STRIDE
        bases_32.append(_stub(tmp_path, entries, b32, name=f"{name}_32.dll")["image_base"])
        bases_64.append(_stub(tmp_path, entries, b64, pe64=True, name=f"{name}_64.dll")["image_base"])

    assert len(set(bases_32)) == len(dll_names)
    assert len(set(bases_64)) == len(dll_names)
    assert not set(bases_32) & set(bases_64)


SPEC = """
# comment
2 stdcall SysAllocString(wstr)
@ stdcall Alpha(long)
1 stdcall -noname Hidden(ptr)
@ stdcall -arch=win64 Only64(ptr)
@ stdcall -arch=!win64 Not64()
5 stdcall -noname -i386 Old386()
@ stdcall EncodePointer(ptr) NTDLL.RtlEncodePointer
@ stdcall Spaced (ptr str long) kernel32.lstrcpynA
@ stdcall Local(long) local_impl
7 stub -noname @
"""


def _snapshot(arch):
    return assign_ordinals(parse_spec(SPEC, ARCH_NAMES[arch]))


def test_snapshot_assigns_free_ordinals_like_winebuild():
    by_name = {e.get("name"): e["ordinal"] for e in _snapshot("x86")}
    # "@" entries fill the free ordinals from the lowest one up
    assert by_name["SysAllocString"] == 2
    assert by_name["Alpha"] == 3


def test_snapshot_arch_filters():
    x86 = {e.get("name") for e in _snapshot("x86")}
    x64 = {e.get("name") for e in _snapshot("x64")}
    assert "Only64" in x64 and "Only64" not in x86
    assert "Not64" in x86 and "Not64" not in x64
    assert "Old386" in x86 and "Old386" not in x64


def test_snapshot_noname_and_forwards():
    entries = {e["ordinal"]: e for e in _snapshot("x86")}
    assert entries[1] == {"ordinal": 1, "name": "Hidden", "noname": True}
    assert entries[7] == {"ordinal": 7, "noname": True}
    by_name = {e.get("name"): e for e in entries.values()}
    assert by_name["EncodePointer"]["forward"] == "NTDLL.RtlEncodePointer"
    assert by_name["Spaced"]["forward"] == "kernel32.lstrcpynA"
    assert "forward" not in by_name["Local"]


def test_extra_exports_fill_only_free_ordinals_and_names():
    entries = [{"ordinal": 390, "name": "ImageList_SetColorTable", "noname": True}]
    extras = [
        {"ordinal": 390, "noname": True},
        {"ordinal": 392, "noname": True},
        {"ordinal": 394, "name": "QuerySystemGestureStatus"},
        {"ordinal": 500, "name": "ImageList_SetColorTable"},
    ]
    merged = add_extra_exports(entries, extras)
    assert [e["ordinal"] for e in merged] == [390, 392, 394]
    assert merged[0]["name"] == "ImageList_SetColorTable"
