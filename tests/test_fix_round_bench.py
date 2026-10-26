#!/usr/bin/env python3
# Eclipse Proving MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# Fix-round regressions — bench defects D-1..D-4 + denied-param
# synonyms, replicating the standing scorecard's failing shapes
# (test-bench/results/eclipse-proving-mcp-2026-10-25.json, B9-B12).

"""Regression tests for the Verity bench defects, shaped exactly
as the bench probed them:

  D-1 (B9): registry entry relabeled qemu emulator->bench with
        adapter=qemu_xsdb must NOT seal a bench pack — refusal at
        open, at connect, and at seal; pack class is the adapter's.
  D-2 (B10): clock-injected bridge, session opened at T, clock
        advanced +7200s past lease_expires_at (mandate in bounds)
        -> LEASE_EXPIRED per op; bench-signed mandate expiring
        12:30 with max_duration_s=7200, clock +2h -> MANDATE_EXPIRED
        per op. No manual expire helper is driven.
  D-3 (B11): JSON-RPC envelope fuzz in a valid sealed-pack
        context — params as bare string/int, tool name as
        list/dict -> structured -32602/-32600, server never dies,
        receipt/audit chains intact after each hostile input.
  D-4 (B12): the live-binding env-var claim exists nowhere.
  Bonus (§6.4): denied-param synonyms pmic / voltage_set / efuse
        map to the PERMANENT refusal codes, not ARGUMENT_UNKNOWN.
"""
import copy
import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).parent.parent
sys.path.insert(0, str(HERE))
import gate_tool  # noqa: E402
import herald_sig  # noqa: E402
import receipts  # noqa: E402
import server  # noqa: E402
from proving_engine import Bridge  # noqa: E402

FIXED = datetime(2026, 10, 25, 12, 0, tzinfo=timezone.utc)
BOARD = "fixture-zcu102-01"
QEMU = "qemu-zcu102-01"
KEYS = json.loads((HERE / "fixtures" / "keys.json").read_text())
HERALD_SEED = hashlib.sha256(b"proving-herald-test-seed-v1").digest()
LIVE_VAR = "ECLIPSE_PROVING_QEMU_" + "LIVE"


def fixed_bridge():
    return Bridge(clock=lambda: FIXED)


def clock_bridge(start):
    cell = [start]
    return Bridge(clock=lambda: cell[0]), cell


def open_session(bridge, mandate="mandate-full", board=BOARD):
    out = bridge.session_open({"mandate": mandate, "board_id": board})
    assert out["ok"], out
    return out["data"]["session_id"]


def op(bridge, tool, sid, **args):
    args["session_id"] = sid
    return bridge.call_session_op(tool, args)


def active_session(bridge, mandate="mandate-full", board=BOARD):
    sid = open_session(bridge, mandate, board)
    assert op(bridge, "target_connect", sid)["ok"]
    assert op(bridge, "target_attest", sid)["ok"]
    return sid


def copied_fixtures_relabel_qemu_to_bench():
    """Bench B9 shape, byte-for-byte: a /tmp COPY of fixtures with
    the qemu board's registry entry target_class relabeled
    emulator->bench, adapter left as qemu_xsdb."""
    tmp = Path(tempfile.mkdtemp(prefix="proving-b9-"))
    fx = tmp / "fixtures"
    shutil.copytree(HERE / "fixtures", fx)
    reg_path = fx / "registry.json"
    reg = json.loads(reg_path.read_text())
    for board in reg["boards"]:
        if board["board_id"] == QEMU:
            assert board["adapter"] == "qemu_xsdb"
            assert board["target_class"] == "emulator"
            board["target_class"] = "bench"
    reg_path.write_text(json.dumps(reg, indent=1, sort_keys=True))
    return fx


class D1ClassIntegrity(unittest.TestCase):
    def test_d1_relabeled_registry_refuses_at_open_no_seal(self):
        fx = copied_fixtures_relabel_qemu_to_bench()
        b = Bridge(fixtures_dir=fx, clock=lambda: FIXED)
        out = b.session_open({"mandate": "mandate-full",
                              "board_id": QEMU})
        self.assertFalse(out["ok"], out)
        self.assertEqual(out["refusal"]["refusal_code"],
                         "TARGET_MISMATCH")
        self.assertIn("receipt_id", out)
        # No session, no lease, no pack — nothing seals as bench.
        self.assertEqual(b.sessions, {})
        self.assertEqual(b.packs, {})
        self.assertNotEqual(
            b.leases.get(QEMU, {}).get("state"), "held")

    def test_d1_connect_recheck_after_post_open_relabel(self):
        b = fixed_bridge()
        sid = open_session(b)
        b.registry[BOARD]["target_class"] = "bench"  # adapter: fixture
        out = op(b, "target_connect", sid)
        self.assertFalse(out["ok"], out)
        self.assertEqual(out["refusal"]["refusal_code"],
                         "TARGET_MISMATCH")
        codes = [r["refusal_code"]
                 for r in b.sessions[sid]["refusals"]]
        self.assertIn("TARGET_MISMATCH", codes)  # receipted

    def test_d1_seal_recheck_after_post_attest_relabel_no_pack(self):
        b = fixed_bridge()
        sid = active_session(b)
        b.registry[BOARD]["target_class"] = "bench"  # adapter: fixture
        out = op(b, "session_close", sid, reason="relabel-then-seal")
        self.assertFalse(out["ok"], out)
        self.assertEqual(out["refusal"]["refusal_code"],
                         "TARGET_MISMATCH")
        self.assertEqual(b.packs, {})  # no pack seals, bench or else
        self.assertNotEqual(b.sessions[sid]["state"], "SEALED")


class D2TimeExpiry(unittest.TestCase):
    def test_d2_lease_expiry_per_op_clock_plus_7200(self):
        b, cell = clock_bridge(FIXED)
        sid = active_session(b)  # lease max_duration_s=3600
        self.assertTrue(op(b, "memory_write", sid, target_id="apu",
                           address=0, bytes_b64="AA==")["ok"])
        cell[0] = FIXED + timedelta(seconds=7200)  # mandate in bounds
        out = op(b, "memory_write", sid, target_id="apu", address=0,
                 bytes_b64="AA==")
        self.assertFalse(out["ok"], out)
        self.assertEqual(out["refusal"]["refusal_code"],
                         "LEASE_EXPIRED")
        self.assertEqual(b.leases[BOARD]["state"], "expired")

    def test_d2_lease_expiry_hits_every_op_incl_status(self):
        b, cell = clock_bridge(FIXED)
        sid = active_session(b)
        cell[0] = FIXED + timedelta(seconds=7200)
        out = op(b, "session_status", sid)
        self.assertFalse(out["ok"], out)
        self.assertEqual(out["refusal"]["refusal_code"],
                         "LEASE_EXPIRED")

    def test_d2_mandate_expiry_per_op(self):
        start = datetime(2026, 10, 25, 10, 30, tzinfo=timezone.utc)
        b, cell = clock_bridge(start)
        mandate = copy.deepcopy(b.mandates["mandate-full"])
        mandate["mandate_id"] = "mandate-bench-expiring"
        mandate["session_bounds"] = {
            **mandate["session_bounds"],
            "not_before": "2026-01-01T00:00:00+00:00",
            "expires_at": "2026-10-25T12:30:00+00:00",
            "max_duration_s": 7200}
        body = {k: v for k, v in mandate.items()
                if k != "herald_signature"}
        mandate["herald_signature"] = herald_sig.sign(
            HERALD_SEED, receipts.canon(body).encode()).hex()
        b.mandates[mandate["mandate_id"]] = mandate
        sid = active_session(b, mandate=mandate)
        self.assertTrue(op(b, "memory_write", sid, target_id="apu",
                           address=0, bytes_b64="AA==")["ok"])
        cell[0] = start + timedelta(hours=2, seconds=1)  # past 12:30
        out = op(b, "memory_write", sid, target_id="apu", address=0,
                 bytes_b64="AA==")
        self.assertFalse(out["ok"], out)
        self.assertEqual(out["refusal"]["refusal_code"],
                         "MANDATE_EXPIRED")


class D3EnvelopeGuards(unittest.TestCase):
    def _bridge_with_sealed_pack(self):
        server.BRIDGE = fixed_bridge()
        b = server.BRIDGE
        sid = active_session(b)
        op(b, "power_set", sid, board_id=BOARD, state="on")
        close = op(b, "session_close", sid, reason="d3-context")
        assert close["ok"], close
        return b, close["data"]["pack_id"]

    def _assert_structured(self, resp):
        self.assertIsInstance(resp, dict)
        self.assertIn("error", resp, resp)
        self.assertIn(resp["error"]["code"], (-32602, -32600), resp)

    def _assert_alive_and_chains_intact(self, b, pack_id):
        resp = server.handle({"jsonrpc": "2.0", "id": 99,
                              "method": "tools/list"})
        self.assertEqual(len(resp["result"]["tools"]), 22)
        resp = server.handle({"jsonrpc": "2.0", "id": 100,
                              "method": "tools/call", "params": {
                                  "name": "pack_verify",
                                  "arguments": {"pack_ref": pack_id}}})
        payload = json.loads(resp["result"]["content"][0]["text"])
        self.assertEqual(payload["data"]["verdict"], "PACK_VALID")
        self.assertTrue(receipts.verify_chain(b.bridge_log.receipts))
        out = gate_tool.pack_verify(b.packs[pack_id],
                                    bytes.fromhex(KEYS["bridge_pubkey"]))
        self.assertEqual(out["verdict"], "PACK_VALID")

    def test_d3_params_as_str_and_int(self):
        b, pack_id = self._bridge_with_sealed_pack()
        for hostile_params in ("power_set", 42):
            resp = server.handle({"jsonrpc": "2.0", "id": 1,
                                  "method": "tools/call",
                                  "params": hostile_params})
            self._assert_structured(resp)
            self._assert_alive_and_chains_intact(b, pack_id)

    def test_d3_name_as_list_and_dict(self):
        b, pack_id = self._bridge_with_sealed_pack()
        for hostile_name in (["power_set"], {"tool": "power_set"}):
            resp = server.handle({"jsonrpc": "2.0", "id": 1,
                                  "method": "tools/call", "params": {
                                      "name": hostile_name,
                                      "arguments": {}}})
            self._assert_structured(resp)
            self._assert_alive_and_chains_intact(b, pack_id)

    def test_d3_nonobject_envelopes(self):
        b, pack_id = self._bridge_with_sealed_pack()
        for hostile_req in (42, "tools/call", ["tools/call"],
                            {"jsonrpc": "2.0", "id": 1,
                             "method": "tools/call",
                             "params": ["power_set"]},
                            {"jsonrpc": "2.0", "id": 1,
                             "method": ["tools/call"]}):
            resp = server.handle(hostile_req)
            self._assert_structured(resp)
        self._assert_alive_and_chains_intact(b, pack_id)


class D4AndBonus(unittest.TestCase):
    def test_d4_no_live_binding_claim_anywhere(self):
        doc = (HERE / "adapters" / "qemu_xsdb.py").read_text()
        self.assertNotIn(LIVE_VAR, doc)
        self.assertIn("No live transport exists in this build", doc)
        for surface in ("README.md", "BUILD-MANIFEST.md",
                        "BUILD-MANIFEST.json", "bazaar-manifest.json"):
            self.assertNotIn(LIVE_VAR, (HERE / surface).read_text(),
                             surface)

    def test_bonus_denied_param_synonyms_permanent_codes(self):
        server.BRIDGE = fixed_bridge()
        for param, code in (("pmic", "PERMANENT_REFUSED_PMIC"),
                            ("voltage_set", "PERMANENT_REFUSED_PMIC"),
                            ("efuse", "PERMANENT_REFUSED_FUSE")):
            resp = server.handle({"jsonrpc": "2.0", "id": 1,
                                  "method": "tools/call", "params": {
                                      "name": "power_set",
                                      "arguments": {
                                          "session_id": "x",
                                          param: 1}}})
            payload = json.loads(resp["result"]["content"][0]["text"])
            self.assertFalse(payload["ok"], (param, payload))
            self.assertEqual(payload["refusal"]["refusal_code"],
                             code, param)
            self.assertIn("receipt_id", payload)  # receipted


if __name__ == "__main__":
    unittest.main(verbosity=2)


# Eclipse Proving MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
