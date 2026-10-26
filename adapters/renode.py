#!/usr/bin/env python3
# Eclipse Proving MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# RenodeAdapter (§4.2) — Renode zynqmp-zcu102 diversity surface.

"""RenodeAdapter — P0 diversity surface: Renode
zynqmp-zcu102-revA/revB, own monitor/GDB, no XSDB — proves the
governance core is adapter-shaped, not XSDB-shaped (§12.2).
Deterministic → CI-grade reruns. Same honesty rule as QEMU:
target_class=emulator, sealed into every pack.
"""
from adapters.base import SimulatedTarget


class RenodeAdapter(SimulatedTarget):
    adapter_name = "renode"
    target_class = "emulator"
    pl_modeled = False

    def connect(self, board_id):
        out = super().connect(board_id)
        out["transport"] = "Renode monitor/GDB (simulated in build env)"
        out["model"] = "zynqmp-zcu102-revA"
        return out


