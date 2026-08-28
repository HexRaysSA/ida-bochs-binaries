# ida-bochs-binaries

An IDA plugin that bundles pre-built Bochs emulator binaries and Windows DLL stubs so that IDA's Bochs debugger works out of the box with no manual Bochs installation. Install the plugin, start debugging.

## Background: How IDA Finds Bochs

IDA locates Bochs through two independent mechanisms: one for the Bochs executable, one for the PE-mode system DLLs.

The Bochs executable (`bochsdbg.exe` on Windows, `bochs` on Unix) is found by `get_bochs_path()`:

1. `BXSHARE` environment variable -- if set and pointing to a valid directory, derives the bochs binary location from it
2. Windows Registry (`HKLM\SOFTWARE\Bochs*`), picking the highest installed version
3. Windows Program Files scan, looking for `Bochs*` directories
4. `PATH`, searching for the executable by name

When `BXSHARE` is set, the `bochsrc.cfg` template's `romimage` and `vgaromimage` lines are filled in with `$BXSHARE`, pointing Bochs to its BIOS ROMs.

IDA also ships `bochsys.dll` / `bochsys32.dll` in `$IDADIR/plugins/bochs/`. These provide a minimal Windows kernel inside the Bochs VM for PE-mode debugging and are not part of the distribution problem.

## What the Plugin Does

The plugin runs as a `PLUGIN_FIX` plugin, so its `init()` is called early -- before any database is open and before the Bochs debugger plugin is loaded. It sets two environment variables:

**`BXSHARE`** points IDA at the bundled Bochs binary and BIOS ROMs. On Unix, this is set to the `share/bochs/` subdirectory. Bochs convention is that `get_bochs_path()` navigates from `$BXSHARE/../../bin/` to find the executable. On Windows, this is the flat directory containing `bochsdbg.exe` alongside the ROM files. If `BXSHARE` is already set by the user, the plugin does not override it. Set at plugin init time.

**`IDABXPATHMAP`** (non-Windows only) maps a host directory of stub DLLs to the guest path `c:\windows\system32\`. This lets the PE-mode loader find Windows system DLLs on Linux and macOS. On Windows, `SearchPath` finds real system DLLs automatically, so this variable is not needed. Set via a `NW_OPENIDB` callback after the database is opened, so the plugin can select the correct stub directory (PE32 or PE32+) based on the loaded file's bitness. IDA's path map does not tolerate mixed-bitness entries: if both 32-bit and 64-bit stubs are mapped, the PE loader encounters the wrong-bitness DLL and fails.

The plugin does not modify `PATH` or any IDA configuration files. On Unix hosts, it also restores the executable bit on the bundled Bochs binary if the plugin installer stripped file modes.

## PE Mode and Windows System DLLs

PE mode needs Windows system DLLs (ntdll.dll, kernel32.dll, etc.) on the host filesystem. The startup script declares DLLs as either `stub` or `load`. For stubbed DLLs, the loader reads only the PE headers and export table from the host file, then generates a replacement stub in the VM. Each exported function either forwards to a bochsys implementation, calls a user-provided handler, or returns 0.

Since the stub system only reads export tables, the DLLs don't need to contain working code. This plugin generates minimal PE files containing only an export directory. The list of exports per DLL is maintained in `data/stubs/exports.json`, a local snapshot derived from [Wine 9.0 `.spec` files](https://gitlab.winehq.org/wine/wine/-/tree/wine-9.0/dlls). The resulting stub DLLs are a few KB each and contain no Wine code, only export name tables.

The 14 DLLs from the default startup script are included: ntdll, kernel32, user32, shell32, shlwapi, urlmon, advapi32, mswsock, wininet, msvcrt, gdi32, ole32, wsock32, ws2_32.

## Plugin Layout

```
ida-bochs-binaries/
├── ida-plugin.json
├── bochs_binaries_entry.py
├── bochs/
│   ├── linux-x86_64/
│   │   ├── bin/bochs
│   │   └── share/bochs/
│   │       ├── BIOS-bochs-latest
│   │       └── VGABIOS-lgpl-latest
│   ├── linux-aarch64/
│   │   ├── bin/bochs
│   │   └── share/bochs/
│   │       ├── BIOS-bochs-latest
│   │       └── VGABIOS-lgpl-latest
│   ├── windows-x86_64/
│   │   ├── bochsdbg.exe
│   │   ├── BIOS-bochs-latest
│   │   └── VGABIOS-lgpl-latest
│   ├── windows-aarch64/
│   │   ├── bochsdbg.exe
│   │   ├── BIOS-bochs-latest
│   │   └── VGABIOS-lgpl-latest
│   └── macos-aarch64/
│       ├── bin/bochs
│       └── share/bochs/
│           ├── BIOS-bochs-latest
│           └── VGABIOS-lgpl-latest
├── data/stubs/windows/
│   ├── ntdll.dll
│   ├── kernel32.dll
│   └── ... (PE32 stub DLLs)
└── data/stubs/windows64/
    ├── ntdll.dll
    ├── kernel32.dll
    └── ... (PE32+ stub DLLs)
```

## Platform Support

| Platform | Bochs Binary | IDA Bochs Debugger |
|----------|-------------|-------------------|
| Linux x86_64 | Included | Supported |
| Linux AArch64 | Included | Supported |
| Windows x86_64 | Included | Supported |
| Windows AArch64 | Included | Not yet shipped by IDA (as of 9.4) |
| macOS AArch64 | Included | Supported |

On Windows ARM64, this plugin installs the Bochs binary and sets `BXSHARE` correctly, but IDA 9.4 does not ship the bochs debugger plugin (`plugins/bochs/bochsys.dll`, `cfg/dbg_bochs.cfg`, `loaders/bochsrc.dll`) for that platform. The Bochs debugger will not be available until a future IDA release adds ARM64 Windows support for these components.

## Building

Bochs is vendored as a git submodule (`vendor/bochs`) pinned to the 2.8 release. The CI workflow builds Bochs from source for each platform with `--enable-debugger` (required for IDA's debugger interface) and `--disable-debugger-gui`.

Stub DLLs are generated by `scripts/generate_stubs.py`, which reads export names from `data/stubs/exports.json` and uses [LIEF](https://lief-project.github.io/) to build minimal PE32 and PE32+ binaries. Each stub gets a deterministic unique preferred image base so IDA's PE-mode image builder does not collide imported DLLs on non-Windows hosts. No network access is needed at build time. To update the export list (e.g. for a newer Wine release), regenerate the JSON from Wine `.spec` files and commit it.

The `package` job assembles all artifacts into a single cross-platform plugin archive and lints it with `hcli plugin lint`.

## License

Bochs is licensed under LGPL-2.1-or-later. The stub DLLs are generated from Wine `.spec` files (LGPL-2.1-or-later); they contain no Wine code, only export name tables derived from the `.spec` files' API descriptions. Source for both is available in the vendored submodule and `scripts/generate_stubs.py`.
