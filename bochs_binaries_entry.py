import logging
import os
import sys

import ida_idaapi

logger = logging.getLogger(__name__)

PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))

PLATFORM_SUBDIRS = {
    ("darwin", "arm64"): "macos-aarch64",
    ("linux", "x86_64"): "linux-x86_64",
    ("linux", "aarch64"): "linux-aarch64",
    ("linux", "arm64"): "linux-aarch64",
    ("win32", "AMD64"): "windows-x86_64",
    ("win32", "ARM64"): "windows-aarch64",
}


def _get_platform_subdir():
    import platform
    return PLATFORM_SUBDIRS.get((sys.platform, platform.machine()))


def _ensure_executable(path):
    try:
        mode = os.stat(path).st_mode
        if mode & 0o111:
            return True
        os.chmod(path, mode | 0o111)
    except OSError as e:
        logger.warning("failed to make bochs executable: %s: %s", path, e)
        return False
    return os.access(path, os.X_OK)


def _setup_bxshare():
    subdir = _get_platform_subdir()
    if not subdir:
        logger.warning("unsupported platform for bochs binaries: %s", sys.platform)
        return False

    bochs_dir = os.path.join(PLUGIN_DIR, "bochs", subdir)
    if not os.path.isdir(bochs_dir):
        logger.warning("bochs binaries not found: %s", bochs_dir)
        return False

    if sys.platform == "win32":
        bxshare = bochs_dir
    else:
        bochs_exe = os.path.join(bochs_dir, "bin", "bochs")
        if not os.path.isfile(bochs_exe):
            logger.warning("bochs executable not found: %s", bochs_exe)
            return False
        if not _ensure_executable(bochs_exe):
            return False
        bxshare = os.path.join(bochs_dir, "share", "bochs")

    if not os.path.isdir(bxshare):
        logger.warning("BXSHARE directory not found: %s", bxshare)
        return False

    if "BXSHARE" in os.environ:
        logger.debug("BXSHARE already set, not overriding: %s", os.environ["BXSHARE"])
        return True

    os.environ["BXSHARE"] = bxshare
    logger.debug("BXSHARE=%s", bxshare)
    return True


_original_idabxpathmap = os.environ.get("IDABXPATHMAP", "")


def _setup_idabxpathmap():
    if sys.platform == "win32":
        return True

    import ida_ida

    stubs_base = os.path.join(PLUGIN_DIR, "data", "stubs")

    if ida_ida.inf_is_64bit():
        stubs_dir = os.path.join(stubs_base, "windows64")
    else:
        stubs_dir = os.path.join(stubs_base, "windows")

    if not os.path.isdir(stubs_dir):
        stubs_dir = os.path.join(stubs_base, "windows")
    if not os.path.isdir(stubs_dir):
        logger.debug("no stub directories found, PE mode may not work on this platform")
        return False

    entries = [stubs_dir + "/=c:/windows/system32/"]

    new_value = ";".join(filter(None, [_original_idabxpathmap] + entries))
    os.environ["IDABXPATHMAP"] = new_value
    logger.debug("IDABXPATHMAP=%s", os.environ["IDABXPATHMAP"])
    return True


def _on_open_idb(nw_code, is_old_database):
    _setup_idabxpathmap()


class bochs_binaries_plugmod_t(ida_idaapi.plugmod_t):
    def run(self, arg):
        pass

    def term(self):
        pass


class bochs_binaries_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_FIX | ida_idaapi.PLUGIN_HIDE | ida_idaapi.PLUGIN_MULTI
    comment = "Provides bundled Bochs binaries for the Bochs debugger"
    wanted_name = "Bochs Binaries"
    wanted_hotkey = ""
    help = ""

    def init(self):
        if not _setup_bxshare():
            return ida_idaapi.PLUGIN_SKIP

        ida_idaapi.notify_when(ida_idaapi.NW_OPENIDB, _on_open_idb)

        logger.info("bochs binaries plugin loaded")
        return bochs_binaries_plugmod_t()


def PLUGIN_ENTRY():
    return bochs_binaries_plugin_t()
