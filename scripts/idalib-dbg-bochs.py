#!/usr/bin/env python3
"""Smoke test: load a PE in Bochs, hit the entry-point breakpoint, single-step."""

import sys
import logging
from pathlib import Path

import idapro

idapro.enable_console_messages(True)

import ida_dbg
import ida_idd
import ida_domain.database

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


def main():
    import os

    target = Path(sys.argv[1]).resolve()
    opts = ida_domain.database.IdaCommandOptions(auto_analysis=True)

    with ida_domain.database.Database.open(str(target), opts, save_on_close=False) as db:
        logger.info("BXSHARE=%s", os.environ.get("BXSHARE", "<not set>"))
        logger.info("IDABXPATHMAP=%s", os.environ.get("IDABXPATHMAP", "<not set>"))
        logger.info("loading bochs debugger")
        if not ida_dbg.load_debugger("bochs", False):
            logger.error("failed to load bochs debugger")
            return 1

        ida_dbg.set_debugger_options(ida_dbg.DOPT_START_BPT)

        logger.info("starting process")
        if ida_dbg.start_process("", "", "") != 1:
            logger.error("failed to start process")
            return 1

        while ida_dbg.get_process_state() != ida_dbg.DSTATE_SUSP:
            ida_dbg.wait_for_next_event(ida_dbg.WFNE_ANY | ida_dbg.WFNE_SUSP, 1000)

        before = ida_dbg.get_ip_val()
        logger.info("before step: %s", hex(before))

        assert ida_dbg.step_into()
        while ida_dbg.wait_for_next_event(ida_dbg.WFNE_ANY | ida_dbg.WFNE_SUSP, 1000) != ida_idd.STEP:
            pass

        after = ida_dbg.get_ip_val()
        logger.info("after step:  %s", hex(after))

        ida_dbg.exit_process()
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_ANY, 1000)

    if after == before:
        logger.error("single-step failed: IP did not advance (stuck at %s)", hex(before))
        return 1

    logger.info("OK: single-step advanced IP from %s to %s", hex(before), hex(after))
    return 0


sys.exit(main())
