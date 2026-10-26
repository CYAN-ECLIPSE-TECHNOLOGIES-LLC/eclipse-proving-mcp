#!/usr/bin/env python3
# Eclipse Proving MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# FixtureAdapter (§4.2) — recorded-trace replay, target_class fixture.

"""FixtureAdapter — recorded XSDB/hw_server traces + serial logs
replayed over the simulated target. Deterministic; the logic-bench
surface for mandate/pin/interlock/gap/receipt code paths (§12.2).
"""
from adapters.base import SimulatedTarget


class FixtureAdapter(SimulatedTarget):
    adapter_name = "fixture"
    target_class = "fixture"
    pl_modeled = False


