#!/usr/bin/env python3
# Eclipse Proving MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# Eclipse Proving P0 tests — spec §13 bench plan, self-run.

"""Eclipse Proving P0 tests, named after spec §13:

  §13.1 functional (happy paths per target class, T0-only, caps)
  §13.2 distinguishing (D-1 one-byte, D-2 dropped session,
        D-3 offline pack verification)
  §13.3 hostile H-1..H-15 (all must refuse BY NAME + receipt)
  §6/§6.4 surface enumeration + denylist source scan
  §9.4 refusal enum verbatim vs the spec text
  house guards + schema-enumerating fuzz with valid context
  adapter parity (X4/X5), HwServer P1 stub, T3 arm/capture/recovery

Verdict ceiling honesty: everything here is fixture/emulator
class. Nothing in this suite is, or claims, bench evidence.
"""
import copy
import json
import sys
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).parent.parent
sys.path.insert(0, str(HERE))
import bridge as bridge_mod  # noqa: E402
import gate_tool  # noqa: E402
import herald_sig  # noqa: E402
import pin_tool  # noqa: E402
import receipts  # noqa: E402
import server  # noqa: E402
from proving_engine import Bridge  # noqa: E402

FIXED = datetime(2026, 10, 25, 12, 0, tzinfo=timezone.utc)
OWNER_SEED = bytes.fromhex(json.loads(
    (HERE / "fixtures" / "owner_key.json").read_text())["seed_hex"])
KEYS = json.loads((HERE / "fixtures" / "keys.json").read_text())
BOARD = "fixture-zcu102-01"


def fresh_bridge():
    return Bridge(clock=lambda: FIXED)


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


def load_elf(bridge, sid, board=BOARD):
    return op(bridge, "artifact_load", sid, board_id=board,
              target_id="apu", artifact_ref="art-zcu102-elf",
              pin_ref="pin-elf-good", artifact_class="elf")


class Functional(unittest.TestCase):
    def test_happy_path_fixture(self):
        b = fresh_bridge()
        disc = b.bench_discover({"mandate_ref": "mandate-full"})
        self.assertTrue(disc["ok"])
        self.assertEqual(len(disc["data"]["boards"]), 4)
        sid = active_session(b)
        self.assertTrue(op(b, "power_set", sid, board_id=BOARD,
                           state="on")["ok"])
        self.assertTrue(load_elf(b, sid)["ok"])
        self.assertTrue(op(b, "target_run", sid, target_id="apu")["ok"])
        console = op(b, "console_read", sid)
        self.assertIn("Linux version", console["data"]["text"])
        close = op(b, "session_close", sid, reason="done")
        self.assertTrue(close["ok"], close)
        pack = b.packs[close["data"]["pack_id"]]
        ok, _ = receipts.verify_pack(
            pack, bytes.fromhex(KEYS["bridge_pubkey"]))
        self.assertTrue(ok)
        verdict = gate_tool.gate_run(
            pack, b.assertion_sets["set-boot-basic"],
            bytes.fromhex(KEYS["bridge_pubkey"]))
        self.assertEqual(verdict["verdict"], "BOOT_VERIFIED")
        self.assertEqual(verdict["target_class"], "fixture")

    def test_read_only_session(self):
        b = fresh_bridge()
        sid = active_session(b, mandate="mandate-t0")
        self.assertTrue(op(b, "register_read", sid, target_id="apu",
                           address=0xFF000000, width=32)["ok"])
        for tool, kw in (("artifact_load", dict(
                board_id=BOARD, target_id="apu",
                artifact_ref="art-zcu102-elf", pin_ref="pin-elf-good",
                artifact_class="elf")),
                ("memory_write", dict(target_id="apu", address=0,
                                      bytes_b64="AA==")),
                ("power_set", dict(board_id=BOARD, state="on")),
                ("persistent_write", dict(
                    board_id=BOARD, media="qspi0",
                    artifact_ref="art-zcu102-boot",
                    pin_ref="pin-boot-good"))):
            out = op(b, tool, sid, **kw)
            self.assertFalse(out["ok"], (tool, out))
            self.assertEqual(out["refusal"]["refusal_code"],
                             "TIER_NOT_GRANTED", tool)

    def test_caps_boundary_exact(self):
        b = fresh_bridge()
        sid = active_session(b, mandate="mandate-capped")
        self.assertTrue(op(b, "memory_read", sid, target_id="apu",
                           address=0, length=1024)["ok"])
        out = op(b, "memory_read", sid, target_id="apu", address=0,
                 length=1)
        self.assertEqual(out["refusal"]["refusal_code"], "CAP_EXCEEDED")
        self.assertTrue(load_elf(b, sid)["ok"])
        out = load_elf(b, sid)
        self.assertEqual(out["refusal"]["refusal_code"], "CAP_EXCEEDED")
        self.assertTrue(op(b, "power_set", sid, board_id=BOARD,
                           state="cycle")["ok"])
        out = op(b, "power_set", sid, board_id=BOARD, state="cycle")
        self.assertEqual(out["refusal"]["refusal_code"], "CAP_EXCEEDED")

    def test_memory_write_readback_and_bounds(self):
        import base64
        b = fresh_bridge()
        sid = active_session(b)
        data = base64.b64encode(b"hello proving").decode()
        out = op(b, "memory_write", sid, target_id="apu", address=16,
                 bytes_b64=data)
        self.assertTrue(out["ok"], out)
        back = op(b, "memory_read", sid, target_id="apu", address=16,
                  length=13)
        self.assertEqual(base64.b64decode(back["data"]["bytes_b64"]),
                         b"hello proving")
        out = op(b, "register_read", sid, target_id="apu",
                 address=0x80000000, width=32)
        self.assertEqual(out["refusal"]["refusal_code"],
                         "ADDRESS_OUT_OF_MAP")
        out = op(b, "memory_write", sid, target_id="apu",
                 address=0x80000000, bytes_b64=data)
        self.assertEqual(out["refusal"]["refusal_code"],
                         "ADDRESS_OUT_OF_MAP")


class Distinguishing(unittest.TestCase):
    def test_d1_one_byte_off(self):
        b = fresh_bridge()
        sid = active_session(b)
        self.assertTrue(load_elf(b, sid)["ok"])
        adapter = b.adapter_for(BOARD)
        calls_before = len(adapter.load_calls)
        att_before = adapter.attest(BOARD)["programmed"]
        out = op(b, "artifact_load", sid, board_id=BOARD,
                 target_id="apu",
                 artifact_ref="art-zcu102-elf-onebyte",
                 pin_ref="pin-elf-good", artifact_class="elf")
        self.assertEqual(out["refusal"]["refusal_code"],
                         "ARTIFACT_PIN_MISMATCH")
        # No load call reached the adapter; board keeps prior state.
        self.assertEqual(len(adapter.load_calls), calls_before)
        self.assertEqual(adapter.attest(BOARD)["programmed"], att_before)
        # Refusal is receipted into the pack.
        close = op(b, "session_close", sid, reason="d1")
        pack = b.packs[close["data"]["pack_id"]]
        codes = [r["refusal_code"] for r in pack["refusals"]]
        self.assertIn("ARTIFACT_PIN_MISMATCH", codes)

    def test_d2_dropped_session(self):
        b = fresh_bridge()
        sid = active_session(b)
        self.assertTrue(load_elf(b, sid)["ok"])
        pack = b.simulate_drop(sid)
        self.assertEqual(len(pack["gap_records"]), 1)
        self.assertEqual(pack["gap_records"][0]["cause"], "drop")
        self.assertEqual(pack["sealed_by"], "bridge (session dropped)")
        ok, _ = receipts.verify_pack(
            pack, bytes.fromhex(KEYS["bridge_pubkey"]))
        self.assertTrue(ok)
        sid2 = open_session(b)
        self.assertTrue(op(b, "target_connect", sid2)["ok"])
        out = op(b, "memory_write", sid2, target_id="apu", address=0,
                 bytes_b64="AA==")
        self.assertEqual(out["refusal"]["refusal_code"],
                         "REATTESTATION_REQUIRED")
        self.assertTrue(op(b, "target_attest", sid2)["ok"])
        self.assertTrue(op(b, "memory_write", sid2, target_id="apu",
                           address=0, bytes_b64="AA==")["ok"])

    def test_d3_offline_pack_verification(self):
        b = fresh_bridge()
        sid = active_session(b)
        op(b, "power_set", sid, board_id=BOARD, state="on")
        load_elf(b, sid)
        op(b, "target_run", sid, target_id="apu")
        close = op(b, "session_close", sid, reason="d3")
        pack = json.loads(json.dumps(b.packs[close["data"]["pack_id"]]))
        # Clean hands: pubkey only, no bridge object involved.
        pub = bytes.fromhex(KEYS["bridge_pubkey"])
        out = gate_tool.pack_verify(pack, pub)
        self.assertEqual(out["verdict"], "PACK_VALID")
        self.assertTrue(any(
            ld["artifact_sha256"] for ld in pack["loads"]))
        verdict = gate_tool.gate_run(
            pack, b.assertion_sets["set-boot-basic"], pub)
        self.assertEqual(verdict["verdict"], "BOOT_VERIFIED")
        self.assertEqual(verdict["target_class"], "fixture")
        self.assertEqual(verdict["set_id"], "set-boot-basic")


class Hostile(unittest.TestCase):
    def test_h1_h2_substitution_and_wrong_board(self):
        b = fresh_bridge()
        sid = active_session(b)
        out = op(b, "artifact_load", sid, board_id=BOARD,
                 target_id="apu", artifact_ref="art-zcu102-elf",
                 pin_ref="pin-wrong-board", artifact_class="elf")
        self.assertEqual(out["refusal"]["refusal_code"],
                         "TARGET_MISMATCH")
        self.assertEqual(b.adapter_for(BOARD).load_calls, [])

    def test_h3_pin_attacks(self):
        b = fresh_bridge()
        data, _ = b.artifact_bytes("art-zcu102-elf")
        for pin_id, code in (("pin-expired", "PIN_EXPIRED"),
                             ("pin-revoked", "PIN_REVOKED"),
                             ("pin-forged", "PIN_SIGNATURE_INVALID")):
            out = pin_tool.pin_verify(
                data, "elf", b.pins[pin_id], b.herald_pub,
                b.revoked_pins, FIXED)
            self.assertEqual(out["verdict"], code, pin_id)
        st = pin_tool.pin_status(b.pins["pin-revoked"],
                                 b.revoked_pins, FIXED)
        self.assertEqual(st["state"], "revoked")

    def test_h4_mandate_attacks(self):
        b = fresh_bridge()
        for mandate, code in (
                ("mandate-forged", "MANDATE_SIGNATURE_INVALID"),
                ("mandate-expired", "MANDATE_EXPIRED"),
                ("mandate-revoked", "MANDATE_REVOKED"),
                ("mandate-other-agent", "AGENT_IDENTITY_UNVERIFIED"),
                ("mandate-unknown", "NO_MANDATE")):
            out = b.session_open({"mandate": mandate, "board_id": BOARD})
            self.assertFalse(out["ok"], mandate)
            self.assertEqual(out["refusal"]["refusal_code"], code,
                             mandate)
        out = b.session_open({"mandate": "mandate-t0",
                              "board_id": "qemu-zcu102-01"})
        self.assertEqual(out["refusal"]["refusal_code"],
                         "BOARD_NOT_IN_MANDATE")

    def test_h5_lease_escape(self):
        b = fresh_bridge()
        sid = open_session(b)
        out = b.session_open({"mandate": "mandate-full",
                              "board_id": BOARD})
        self.assertEqual(out["refusal"]["refusal_code"], "LEASE_HELD")
        self.assertIn(sid, out["refusal"]["detail"])
        b.expire_lease(BOARD)
        out = op(b, "session_status", sid)
        self.assertEqual(out["refusal"]["refusal_code"], "LEASE_EXPIRED")

    def test_h6_tcl_smuggling(self):
        server.BRIDGE = fresh_bridge()
        resp = server.handle({"jsonrpc": "2.0", "id": 1,
                              "method": "tools/call", "params": {
                                  "name": "console_read",
                                  "arguments": {"session_id": "x",
                                                "tcl": "connect; "
                                                       "program_hw"}}})
        payload = json.loads(resp["result"]["content"][0]["text"])
        self.assertEqual(payload["refusal"]["refusal_code"],
                         "OP_NOT_IN_MANDATE")
        sid = active_session(server.BRIDGE)
        out = op(server.BRIDGE, "console_read", sid,
                 since_receipt="exec tcl; program_hw_devices")
        self.assertTrue(out["ok"])  # inert data, never executed
        self.assertEqual(server.BRIDGE.adapter_for(BOARD).load_calls,
                         [])

    def test_h7_no_unauthenticated_adapter_path(self):
        # Architecture assertion: adapter_for is reached only from
        # receipted op handlers, pin check, seal, or admin/test code.
        src = (HERE / "proving_engine.py").read_text()
        import re as _re
        callers = set()
        current = None
        for line in src.splitlines():
            m = _re.match(r"    def (\w+)", line)
            if m:
                current = m.group(1)
            if "adapter_for(" in line and "def adapter_for" not in line:
                callers.add(current)
        allowed = {c for c in callers if c and (
            c.startswith("_t_") or c in (
                "_pin_check", "_seal_session", "simulate_drop"))}
        self.assertEqual(callers, allowed, callers)
        # And a bare adapter object carries no receipt machinery:
        adapter = fresh_bridge().adapter_for(BOARD)
        self.assertFalse(hasattr(adapter, "receipts"))

    def test_h8_t3_gates(self):
        b = fresh_bridge()
        sid = active_session(b)
        out = op(b, "persistent_write", sid, board_id=BOARD,
                 media="qspi0", artifact_ref="art-zcu102-boot",
                 pin_ref="pin-boot-good")
        self.assertEqual(out["refusal"]["refusal_code"],
                         "TIER_NOT_ARMED")
        b.admin_tier_arm(BOARD, sid, OWNER_SEED)
        adapter = b.adapter_for(BOARD)
        media_before = adapter.persistent_read("qspi0")
        out = op(b, "persistent_write", sid, board_id=BOARD,
                 media="qspi0", artifact_ref="art-zcu102-boot",
                 pin_ref="pin-boot-good")
        self.assertEqual(out["refusal"]["refusal_code"],
                         "PREWRITE_CAPTURE_REQUIRED")
        self.assertEqual(adapter.persistent_read("qspi0"), media_before)
        cap = op(b, "persistent_capture", sid, media="qspi0")
        self.assertTrue(cap["ok"], cap)
        out = op(b, "persistent_write", sid, board_id=BOARD,
                 media="qspi0", artifact_ref="art-zcu102-boot",
                 pin_ref="pin-boot-good")
        self.assertTrue(out["ok"], out)
        self.assertNotEqual(adapter.persistent_read("qspi0"),
                            media_before)
        # No-recovery board: arm + capture still refuse.
        sid2 = active_session(b, board="fixture-norecovery-01")
        b.admin_tier_arm("fixture-norecovery-01", sid2, OWNER_SEED)
        self.assertTrue(op(b, "persistent_capture", sid2,
                           media="qspi0")["ok"])
        out = op(b, "persistent_write", sid2,
                 board_id="fixture-norecovery-01", media="qspi0",
                 artifact_ref="art-zcu102-boot",
                 pin_ref="pin-boot-good")
        self.assertEqual(out["refusal"]["refusal_code"],
                         "RECOVERY_PATH_UNRECORDED")

    def test_h8b_arm_tamper_and_expiry_at_close(self):
        b = fresh_bridge()
        sid = active_session(b)
        arm = b.admin_tier_arm(BOARD, sid, OWNER_SEED)
        arm["recovery_path_ref"] = "tampered-after-signing"
        out = op(b, "persistent_capture", sid, media="qspi0")
        self.assertEqual(out["refusal"]["refusal_code"],
                         "TIER_NOT_ARMED")
        # Arm dies with its session (§5.2).
        b2 = fresh_bridge()
        s1 = active_session(b2)
        b2.admin_tier_arm(BOARD, s1, OWNER_SEED)
        op(b2, "session_close", s1, reason="x")
        s2 = active_session(b2)
        out = op(b2, "persistent_write", s2, board_id=BOARD,
                 media="qspi0", artifact_ref="art-zcu102-boot",
                 pin_ref="pin-boot-good")
        self.assertEqual(out["refusal"]["refusal_code"],
                         "TIER_NOT_ARMED")

    def test_h9_revocation_mid_write_dead_man(self):
        b = fresh_bridge()
        sid = active_session(b)
        op(b, "power_set", sid, board_id=BOARD, state="on")
        adapter = b.adapter_for(BOARD)
        result = {}

        def do_load():
            result["out"] = op(b, "artifact_load", sid, board_id=BOARD,
                               target_id="apu",
                               artifact_ref="art-slow-elf",
                               pin_ref="pin-slow-elf",
                               artifact_class="elf")
        t = threading.Thread(target=do_load)
        t.start()
        # Wait until the write window is genuinely active.
        for _ in range(500):
            if b.sessions[sid]["write_window"]:
                break
            threading.Event().wait(0.01)
        self.assertTrue(b.sessions[sid]["write_window"])
        out = op(b, "power_set", sid, board_id=BOARD, state="off")
        self.assertEqual(out["refusal"]["refusal_code"],
                         "POWER_WINDOW_ACTIVE")
        b.admin_mandate_revoke("mandate-full")
        adapter.release_window()
        t.join(timeout=30)
        self.assertTrue(result["out"]["ok"], result)  # write completed
        self.assertEqual(adapter.power, "on")          # never cut
        out = op(b, "memory_write", sid, target_id="apu", address=0,
                 bytes_b64="AA==")
        self.assertEqual(out["refusal"]["refusal_code"],
                         "SESSION_FROZEN")

    def test_h10_power_during_window_not_queued(self):
        b = fresh_bridge()
        sid = active_session(b)
        session = b.sessions[sid]
        session["write_window"] = {"op_id": "op-x",
                                    "tool": "artifact_load"}
        out = op(b, "power_set", sid, board_id=BOARD, state="off")
        self.assertEqual(out["refusal"]["refusal_code"],
                         "POWER_WINDOW_ACTIVE")
        self.assertEqual(b.adapter_for(BOARD).power, "off")
        session["write_window"] = None
        # Not queued: no power act was recorded for the refused op.
        self.assertEqual(session["power_acts"], [])

    def test_h11_permanent_ops_absent(self):
        names = [t["name"] for t in server.tool_list()]
        self.assertEqual(len(names), 22)
        for bad in ("fuse", "pmic", "voltage", "strap", "tcl", "xsdb",
                    "shell", "arm", "freeze", "revoke"):
            self.assertFalse(any(bad in n for n in names), bad)
        for name in ("fuse_program", "voltage_set", "exec_tcl",
                     "tier_arm", "strap_set"):
            resp = server.handle({"jsonrpc": "2.0", "id": 1,
                                  "method": "tools/call",
                                  "params": {"name": name,
                                             "arguments": {}}})
            self.assertEqual(resp["error"]["code"], -32602, name)
        # Denied params map to permanent codes at the boundary.
        server.BRIDGE = fresh_bridge()
        resp = server.handle({"jsonrpc": "2.0", "id": 1,
                              "method": "tools/call", "params": {
                                  "name": "power_set",
                                  "arguments": {"session_id": "x",
                                                "voltage": 1.8}}})
        payload = json.loads(resp["result"]["content"][0]["text"])
        self.assertEqual(payload["refusal"]["refusal_code"],
                         "PERMANENT_REFUSED_PMIC")
        # Source scan: no fuse/PMIC/strap-set call sites in adapters
        # (identifier-level: "_refused" contains the letters f-u-s-e
        # and is not a call site; what must not exist is a def or a
        # call naming the permanent acts).
        import re as _re
        for f in (HERE / "adapters").glob("*.py"):
            text = f.read_text()
            self.assertIsNone(_re.search(
                r"def \w*(program_fuse|set_voltage|strap_set|"
                r"pmic_config)", text), f)
            self.assertIsNone(_re.search(
                r"\b(program_fuse|set_voltage|pmic_config|"
                r"strap_set)\s*\(", text), f)

    def test_h12_evidence_sabotage(self):
        b = fresh_bridge()
        sid = active_session(b)
        b.inject_evidence_failure = True
        out = op(b, "memory_write", sid, target_id="apu", address=0,
                 bytes_b64="AA==")
        self.assertEqual(out["refusal"]["refusal_code"],
                         "EVIDENCE_PACK_FAILURE")
        self.assertEqual(b.sessions[sid]["state"], "EVIDENCE_HALTED")
        self.assertTrue(op(b, "memory_read", sid, target_id="apu",
                           address=0, length=4)["ok"])  # reads live
        out = op(b, "power_set", sid, board_id=BOARD, state="on")
        self.assertEqual(out["refusal"]["refusal_code"],
                         "EVIDENCE_PACK_FAILURE")
        close = op(b, "session_close", sid, reason="halted")
        self.assertTrue(close["ok"], close)
        pack = b.packs[close["data"]["pack_id"]]
        pub = bytes.fromhex(KEYS["bridge_pubkey"])
        # Post-hoc tamper variants all fail.
        v1 = copy.deepcopy(pack)
        v1["operations"][1]["tool"] = "tampered_op"
        self.assertFalse(receipts.verify_pack(v1, pub)[0])
        v2 = copy.deepcopy(pack)
        v2["refusals"] = []
        self.assertFalse(receipts.verify_pack(v2, pub)[0])
        v3 = copy.deepcopy(pack)
        v3["receipts"] = list(reversed(v3["receipts"]))
        self.assertFalse(receipts.verify_pack(v3, pub)[0])
        # Seal failure: a session that cannot seal does not close.
        b2 = fresh_bridge()
        s2 = active_session(b2)
        b2.inject_seal_failure = True
        out = op(b2, "session_close", s2, reason="x")
        self.assertEqual(out["refusal"]["refusal_code"],
                         "EVIDENCE_PACK_FAILURE")
        self.assertNotEqual(b2.sessions[s2]["state"], "SEALED")

    def test_h13_class_laundering(self):
        b = fresh_bridge()
        sid = active_session(b, board="qemu-zcu102-01")
        close = op(b, "session_close", sid, reason="x")
        pack = b.packs[close["data"]["pack_id"]]
        self.assertEqual(pack["target_class"], "emulator")
        pub = bytes.fromhex(KEYS["bridge_pubkey"])
        stripped = copy.deepcopy(pack)
        del stripped["target_class"]
        self.assertFalse(receipts.verify_pack(stripped, pub)[0])
        relabeled = copy.deepcopy(pack)
        relabeled["target_class"] = "bench"
        self.assertFalse(receipts.verify_pack(relabeled, pub)[0])
        for t in server.tool_list():
            self.assertNotIn("target_class",
                             t["inputSchema"]["properties"])

    def test_h14_wildcards(self):
        b = fresh_bridge()
        out = b.session_open({"mandate": "mandate-full",
                              "board_id": "*"})
        self.assertEqual(out["refusal"]["refusal_code"],
                         "BOARD_WILDCARD_REFUSED")
        sid = active_session(b)
        out = op(b, "power_set", sid, board_id="*", state="on")
        self.assertEqual(out["refusal"]["refusal_code"],
                         "BOARD_WILDCARD_REFUSED")
        out = op(b, "power_set", sid, board_id="attached", state="on")
        self.assertEqual(out["refusal"]["refusal_code"],
                         "BOARD_NOT_IN_MANDATE")

    def test_h15_replay_is_a_new_session(self):
        b = fresh_bridge()
        sid = active_session(b)
        load_elf(b, sid)
        close = op(b, "session_close", sid, reason="first")
        old_pack = b.packs[close["data"]["pack_id"]]
        sid2 = open_session(b)
        self.assertNotEqual(sid, sid2)
        new_genesis = b.sessions[sid2]["chain"].receipts[0]
        old_ids = {r["receipt_id"] for r in old_pack["receipts"]}
        self.assertNotIn(new_genesis["receipt_id"], old_ids)
        out = op(b, "memory_write", sid2, target_id="apu", address=0,
                 bytes_b64="AA==")
        self.assertIn(out["refusal"]["refusal_code"],
                      ("BOARD_STATE_UNKNOWN", "REATTESTATION_REQUIRED"))

    def test_bench_freeze_semantics(self):
        b = fresh_bridge()
        sid = active_session(b)
        b.admin_bench_freeze_set(True)
        self.assertTrue(op(b, "memory_read", sid, target_id="apu",
                           address=0, length=8)["ok"])
        out = load_elf(b, sid)
        self.assertEqual(out["refusal"]["refusal_code"],
                         "BENCH_FROZEN")
        out = op(b, "power_set", sid, board_id=BOARD, state="on")
        self.assertEqual(out["refusal"]["refusal_code"],
                         "BENCH_FROZEN")


class SurfaceAndSpec(unittest.TestCase):
    EXPECTED_TOOLS = [
        "bench_discover", "session_open", "session_status",
        "target_connect", "target_attest", "register_read",
        "memory_read", "console_read", "artifact_load",
        "memory_write", "target_run", "target_halt", "power_set",
        "target_reset", "persistent_write", "session_close",
        "pin_verify", "pin_show", "pin_status", "gate_run",
        "pack_verify", "gate_assertions_check"]

    def test_tool_surface_exactly_22(self):
        self.assertEqual([t["name"] for t in server.tool_list()],
                         self.EXPECTED_TOOLS)

    def test_refusal_enum_matches_spec_verbatim(self):
        import re as _re
        spec = (HERE.parent /
                "eclipse-proving-spec-20261025.md").read_text()
        section = spec.split("### 9.4")[1].split("### 9.5")[0]
        codes = set(_re.findall(r"`([A-Z][A-Z_]{3,})`", section))
        import proving_engine
        self.assertEqual(codes, set(proving_engine.REFUSALS))

    def test_gate_unknown_assertion_refuses(self):
        b = fresh_bridge()
        out = bridge_mod.tool_gate_assertions_check(
            b, {"assertion_set_ref": "set-bad-vocab"})
        self.assertFalse(out["ok"])
        self.assertEqual(out["refusal"]["refusal_code"],
                         "ASSERTION_TYPE_UNKNOWN")
        out = bridge_mod.tool_gate_assertions_check(
            b, {"assertion_set_ref": "set-boot-basic"})
        self.assertTrue(out["ok"], out)

    def test_ed25519_rfc8032_vector(self):
        seed = bytes.fromhex(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac"
            "031cae7f60")
        _, pk = herald_sig.keypair_from_seed(seed)
        self.assertEqual(
            pk.hex(),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021"
            "a68f707511a")
        sig = herald_sig.sign(seed, b"")
        self.assertTrue(herald_sig.verify(pk, b"", sig))
        self.assertFalse(herald_sig.verify(pk, b"x", sig))


class AdapterParity(unittest.TestCase):
    def _run_board(self, board, artifact, pin, aset):
        b = fresh_bridge()
        sid = active_session(b, board=board)
        op(b, "power_set", sid, board_id=board, state="on")
        out = op(b, "artifact_load", sid, board_id=board,
                 target_id="apu", artifact_ref=artifact,
                 pin_ref=pin, artifact_class="elf")
        self.assertTrue(out["ok"], out)
        op(b, "target_run", sid, target_id="apu")
        close = op(b, "session_close", sid, reason="parity")
        pack = b.packs[close["data"]["pack_id"]]
        verdict = gate_tool.gate_run(
            pack, b.assertion_sets[aset],
            bytes.fromhex(KEYS["bridge_pubkey"]))
        return pack, verdict

    def test_x4_qemu_happy(self):
        pack, verdict = self._run_board(
            "qemu-zcu102-01", "art-qemu-elf", "pin-qemu-elf",
            "set-qemu-boot")
        self.assertEqual(pack["target_class"], "emulator")
        self.assertEqual(verdict["verdict"], "BOOT_VERIFIED")
        self.assertEqual(verdict["target_class"], "emulator")

    def test_x5_renode_parity(self):
        pack, verdict = self._run_board(
            "renode-zcu102-01", "art-renode-elf", "pin-renode-elf",
            "set-renode-boot")
        self.assertEqual(pack["target_class"], "emulator")
        self.assertEqual(verdict["verdict"], "BOOT_VERIFIED")

    def test_hwserver_stub_p1_only(self):
        from adapters import make_adapter
        from adapters.base import AdapterError
        adapter = make_adapter({"board_id": "x", "adapter": "hwserver",
                                "board_rev": "1", "device_part": "p",
                                "targets": [], "media": []})
        with self.assertRaises(AdapterError):
            adapter.connect("x")


class Fuzz(unittest.TestCase):
    MUTATIONS = [None, True, 1.5, [], {}, "x", -1, "0xZZ", 10 ** 12,
                 {"nested": [1, 2]}]

    def test_schema_enumerating_fuzz_valid_context(self):
        server.BRIDGE = fresh_bridge()
        b = server.BRIDGE
        sid = active_session(b)
        op(b, "power_set", sid, board_id=BOARD, state="on")
        load_elf(b, sid)
        op(b, "target_run", sid, target_id="apu")
        close = op(b, "session_close", sid, reason="fuzz-context")
        pack_id = close["data"]["pack_id"]
        valid = {
            "bench_discover": {"mandate_ref": "mandate-full"},
            "session_open": {"mandate": "mandate-t0",
                             "board_id": BOARD},
            "session_status": {"session_id": sid},
            "target_connect": {"session_id": sid},
            "target_attest": {"session_id": sid},
            "register_read": {"session_id": sid, "target_id": "apu",
                              "address": 0xFF000000, "width": 32},
            "memory_read": {"session_id": sid, "target_id": "apu",
                            "address": 0, "length": 16},
            "console_read": {"session_id": sid, "max_bytes": 512},
            "artifact_load": {"session_id": sid, "board_id": BOARD,
                              "target_id": "apu",
                              "artifact_ref": "art-zcu102-elf",
                              "pin_ref": "pin-elf-good",
                              "artifact_class": "elf"},
            "memory_write": {"session_id": sid, "target_id": "apu",
                             "address": 0, "bytes_b64": "AA=="},
            "target_run": {"session_id": sid, "target_id": "apu"},
            "target_halt": {"session_id": sid, "target_id": "apu"},
            "power_set": {"session_id": sid, "board_id": BOARD,
                          "state": "on"},
            "target_reset": {"session_id": sid, "target_id": "apu",
                             "kind": "core"},
            "persistent_write": {"session_id": sid, "board_id": BOARD,
                                 "media": "qspi0",
                                 "artifact_ref": "art-zcu102-boot",
                                 "pin_ref": "pin-boot-good"},
            "session_close": {"session_id": sid, "reason": "fuzz"},
            "pin_verify": {"artifact_ref": "art-zcu102-elf",
                           "pin_ref": "pin-elf-good"},
            "pin_show": {"pin_ref": "pin-elf-good"},
            "pin_status": {"pin_ref": "pin-elf-good"},
            "gate_run": {"pack_ref": pack_id,
                         "assertion_set_ref": "set-boot-basic"},
            "pack_verify": {"pack_ref": pack_id},
            "gate_assertions_check":
                {"assertion_set_ref": "set-boot-basic"},
        }
        checked = 0
        for tool, base_args in valid.items():
            for param in list(base_args):
                for mutation in self.MUTATIONS:
                    args = dict(base_args)
                    args[param] = mutation
                    resp = server.handle({
                        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                        "params": {"name": tool, "arguments": args}})
                    self.assertIsInstance(resp, dict)
                    self.assertTrue("result" in resp or "error" in resp,
                                    (tool, param, mutation, resp))
                    if "result" in resp:
                        json.loads(resp["result"]["content"][0]["text"])
                    checked += 1
        # Full enumeration: every param of every tool x 10 mutations.
        self.assertGreater(checked, 450)
        # Unknown + fuzzed tool names: structured -32602, never a crash.
        for name in ("fuse_program", "exec_tcl", "", "ARTIFACT_LOAD",
                     "session_open2", None, 42):
            resp = server.handle({"jsonrpc": "2.0", "id": 1,
                                  "method": "tools/call",
                                  "params": {"name": name,
                                             "arguments": {}}})
            self.assertEqual(resp["error"]["code"], -32602, name)
        # Non-object arguments: structured refusal, never a crash.
        resp = server.handle({"jsonrpc": "2.0", "id": 1,
                              "method": "tools/call",
                              "params": {"name": "pin_show",
                                         "arguments": [1, 2]}})
        self.assertEqual(resp["error"]["code"], -32602)


if __name__ == "__main__":
    unittest.main(verbosity=2)


# Eclipse Proving MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
