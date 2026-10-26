# Eclipse Proving MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
"""Adapter registry (§4.2): one interface, four implementations."""
from adapters.fixture import FixtureAdapter
from adapters.hwserver import HwServerAdapter
from adapters.qemu_xsdb import QemuXsdbAdapter
from adapters.renode import RenodeAdapter

ADAPTERS = {
    "fixture": FixtureAdapter,
    "qemu_xsdb": QemuXsdbAdapter,
    "renode": RenodeAdapter,
    "hwserver": HwServerAdapter,
}


def make_adapter(board: dict):
    cls = ADAPTERS.get(board.get("adapter"))
    if cls is None:
        raise ValueError(f"ADAPTER_UNKNOWN: {board.get('adapter')}")
    return cls(board)
