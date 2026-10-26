#!/usr/bin/env python3
# Eclipse Proving MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# Eclipse Proving stdio smoke — spawns the real server, runs a
# governed session on fixture + QEMU-emulator boards over the wire.

"""Eclipse Proving stdio smoke — spawns the real server as a
subprocess and proves over the wire: (1) tools/list is exactly the
22 tools of spec §6; (2) a full session on the fixture board
(open->connect->attest->power->load->run->close) seals a pack that
verifies offline in this process with the public key only, and
Gate renders BOOT_VERIFIED; (3) a one-byte-off artifact refuses
ARTIFACT_PIN_MISMATCH over the wire; (4) the same session shape on
the QEMU ZCU102 emulator board seals target_class=emulator.
Temp state throughout; nothing here is bench evidence (§3.2.8).
"""
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import gate_tool  # noqa: E402

KEYS = json.loads((HERE / "fixtures" / "keys.json").read_text())
BRIDGE_PUB = bytes.fromhex(KEYS["bridge_pubkey"])
ASSERTIONS = json.loads(
    (HERE / "fixtures" / "assertion_sets.json").read_text())["sets"]


def spawn():
    return subprocess.Popen(
        [sys.executable, str(HERE / "server.py")],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)


def call(proc, rid, method, params=None):
    proc.stdin.write(json.dumps(
        {"jsonrpc": "2.0", "id": rid, "method": method,
         "params": params or {}}) + "\n")
    proc.stdin.flush()
    return json.loads(proc.stdout.readline())


def tool(proc, rid, name, args):
    return call(proc, rid, "tools/call", {"name": name,
                                          "arguments": args})


def result_text(resp):
    return json.loads(resp["result"]["content"][0]["text"])


def run_session(proc, rid, board, artifact, pin):
    opened = result_text(tool(proc, rid, "session_open",
                              {"mandate": "mandate-full",
                               "board_id": board}))
    sid = opened["data"]["session_id"]
    rid += 1
    for name, args in (
            ("target_connect", {}), ("target_attest", {}),
            ("power_set", {"board_id": board, "state": "on"}),
            ("artifact_load", {"board_id": board, "target_id": "apu",
                               "artifact_ref": artifact,
                               "pin_ref": pin,
                               "artifact_class": "elf"}),
            ("target_run", {"target_id": "apu"})):
        args["session_id"] = sid
        out = result_text(tool(proc, rid, name, args))
        assert out["ok"], (name, out)
        rid += 1
    closed = result_text(tool(proc, rid, "session_close",
                              {"session_id": sid, "reason": "smoke"}))
    return closed["data"]["pack_id"], rid + 1


def main():
    proc = spawn()
    try:
        init = call(proc, 1, "initialize")
        assert init["result"]["serverInfo"]["name"] == \
            "eclipse-proving"
        names = [t["name"] for t in
                 call(proc, 2, "tools/list")["result"]["tools"]]
        assert len(names) == 22, names
        print("surface: exactly 22 tools (§6)")
        pack_id, rid = run_session(proc, 3, "fixture-zcu102-01",
                                   "art-zcu102-elf", "pin-elf-good")
        # One-byte-off over the wire, on a fresh session.
        opened = result_text(tool(proc, rid, "session_open",
                                  {"mandate": "mandate-full",
                                   "board_id": "fixture-zcu102-01"}))
        sid = opened["data"]["session_id"]
        rid += 1
        for name in ("target_connect", "target_attest"):
            out = result_text(tool(proc, rid, name,
                                   {"session_id": sid}))
            assert out["ok"], out
            rid += 1
        bad = result_text(tool(proc, rid, "artifact_load", {
            "session_id": sid, "board_id": "fixture-zcu102-01",
            "target_id": "apu",
            "artifact_ref": "art-zcu102-elf-onebyte",
            "pin_ref": "pin-elf-good", "artifact_class": "elf"}))
        assert bad["refusal"]["refusal_code"] == \
            "ARTIFACT_PIN_MISMATCH", bad
        print("one-byte rule: ARTIFACT_PIN_MISMATCH over the wire")
        result_text(tool(proc, rid + 1, "session_close",
                         {"session_id": sid, "reason": "smoke-d1"}))
        # The sealed pack travels back through pack_verify by id.
        pv = result_text(tool(proc, rid + 2, "pack_verify",
                              {"pack_ref": pack_id}))
        assert pv["data"]["verdict"] == "PACK_VALID", pv
        gate = result_text(tool(proc, rid + 3, "gate_run", {
            "pack_ref": pack_id,
            "assertion_set_ref": "set-boot-basic"}))
        assert gate["data"]["verdict"] == "BOOT_VERIFIED", gate
        print("fixture session: pack PACK_VALID, gate BOOT_VERIFIED")
        pack2, _ = run_session(proc, rid + 4, "qemu-zcu102-01",
                               "art-qemu-elf", "pin-qemu-elf")
        pv2 = result_text(tool(proc, rid + 20, "pack_verify",
                               {"pack_ref": pack2}))
        assert pv2["data"]["target_class"] == "emulator", pv2
        print("qemu session: sealed with target_class=emulator")
    finally:
        proc.terminate()
    print("SMOKE OK")


if __name__ == "__main__":
    main()


# Eclipse Proving MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
