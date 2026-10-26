#!/usr/bin/env python3
# Eclipse Proving MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# QemuXsdbAdapter (§4.2/§12.2) — AMD QEMU (Xilinx fork), ZCU102.

"""QemuXsdbAdapter — P0 PRIMARY target (owner-confirmed 2026-10-25:
AMD QEMU (Xilinx fork), ZCU102; spec §12.1 pin satisfied).

No live transport exists in this build: no code in this adapter
(or anywhere in the tree) binds a real XSDB/GDB/TCF session, and
no environment variable, flag, or config enables one — a live
binding is future deployment work, not a switch. In this build
environment no QEMU process is present, so the adapter runs its
XSDB-shaped session script against the deterministic simulated
PS and declares target_class=emulator in every record — emulator
success never upgrades a physical-layer claim (§3.2.8). PL is
NOT modeled by plain QEMU (§12.2): bitstream loads are recorded
with that semantics note and no PL-behavior claim.
"""
from adapters.base import SimulatedTarget


class QemuXsdbAdapter(SimulatedTarget):
    adapter_name = "qemu_xsdb"
    target_class = "emulator"
    pl_modeled = False

    def connect(self, board_id):
        out = super().connect(board_id)
        out["transport"] = "XSDB via GDB/TCF (simulated PS in build env)"
        out["model"] = "AMD QEMU (Xilinx fork) xilinx-zcu102"
        return out


