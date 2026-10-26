#!/usr/bin/env python3
# Eclipse Proving MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# HwServerAdapter (§4.2) — P1 ONLY interface stub, no implementation.

"""HwServerAdapter — interface defined at P0; NO implementation,
no physical claim at P0 (§12.5). Every method raises
ADAPTER_NOT_IN_PHASE by name. Real hw_server + XSDB + serial +
PDU/USB power land at P1 behind the §13.5 bench additions.
"""
from adapters.base import AdapterError

_PHASE = "ADAPTER_NOT_IN_PHASE: HwServerAdapter is P1 only (spec §12.5)"


class HwServerAdapter:
    adapter_name = "hwserver"
    target_class = "bench"

    def __init__(self, board):
        self.board = board

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)

        def _blocked(*a, **k):
            raise AdapterError(_PHASE)
        return _blocked


