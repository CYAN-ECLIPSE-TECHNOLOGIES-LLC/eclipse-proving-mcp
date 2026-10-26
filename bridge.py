#!/usr/bin/env python3
# Eclipse Proving MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# Proving bridge — standalone Pin/Gate tool functions + owner admin
# CLI (§6.2). The bridge core itself lives in proving_engine.Bridge.

"""Eclipse Proving bridge surface: Pin/Gate standalone tools + the
owner/admin CLI (spec §6.2 — NOT MCP tools; the agent surface has
no path to any of them, bench-asserted H-11).

Standalone tools (17-22) run against the bridge's stores in-process,
and equally from the CLIs at the bottom of pin_tool/gate_tool
consumers — offline, in third-party hands, with no bridge contact
required for pack_verify (D-3): a pack dict + the bridge public
key is all they need.

Admin CLI (this file, owner-authenticated by possession of the
owner key file): bench_freeze_set · tier_arm · lease_release ·
mandate_revoke · pack_export. Live-process acts use the in-process
Bridge.admin_* methods; the CLI persists acts to
control.local.json / arms.local.json beside the fixtures, which a
bridge process loads at start (proving_engine.Bridge.__init__).
"""
import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

import gate_tool  # noqa: E402
import herald_sig  # noqa: E402
import pin_tool  # noqa: E402
from proving_engine import Bridge, Refusal, ToolError  # noqa: E402

__all__ = ["Bridge"]


# ------------------------------------------------------- Pin (17-19)
def tool_pin_verify(bridge, args):
    def fn():
        pin = bridge.resolve_pin(args.get("pin_ref"))
        data, _ = bridge.artifact_bytes(args.get("artifact_ref"))
        if data is None:
            raise Refusal("ARTIFACT_PIN_MISMATCH",
                          "artifact not present in the artifact store")
        return pin_tool.pin_verify(
            data, pin["artifact_class"], pin, bridge.herald_pub,
            bridge.revoked_pins, bridge.now())
    return bridge._log_call("pin_verify", args, fn)


def tool_pin_show(bridge, args):
    def fn():
        pin = bridge.resolve_pin(args.get("pin_ref"))
        return pin_tool.pin_show(pin, bridge.herald_pub)
    return bridge._log_call("pin_show", args, fn)


def tool_pin_status(bridge, args):
    def fn():
        pin = bridge.resolve_pin(args.get("pin_ref"))
        return pin_tool.pin_status(pin, bridge.revoked_pins,
                                   bridge.now())
    return bridge._log_call("pin_status", args, fn)


# ------------------------------------------------------- Gate (20-22)
def _resolve_pack(bridge, ref):
    if isinstance(ref, dict):
        return ref
    if isinstance(ref, str) and ref in bridge.packs:
        return bridge.packs[ref]
    if not isinstance(ref, str):
        raise ToolError(f"REFERENCE_TYPE_INVALID: pack_ref must be a "
                        f"string ref or a pack object (got "
                        f"{type(ref).__name__})")
    raise ToolError(f"PACK_UNKNOWN: {ref!r} is not a sealed pack "
                    "known to this bridge")


def _resolve_assertion_set(bridge, ref):
    if isinstance(ref, dict):
        return ref
    if isinstance(ref, str) and ref in bridge.assertion_sets:
        return bridge.assertion_sets[ref]
    if not isinstance(ref, str):
        raise ToolError(f"REFERENCE_TYPE_INVALID: assertion_set_ref "
                        f"must be a string ref or a set object (got "
                        f"{type(ref).__name__})")
    raise ToolError(f"ASSERTION_SET_UNKNOWN: {ref!r}")


def tool_gate_run(bridge, args):
    def fn():
        pack = _resolve_pack(bridge, args.get("pack_ref"))
        aset = _resolve_assertion_set(bridge, args.get("assertion_set_ref"))
        from proving_engine import now_iso
        return gate_tool.gate_run(pack, aset, bridge.bridge_pub,
                                  at=now_iso(bridge.now()))
    return bridge._log_call("gate_run", args, fn)


def tool_pack_verify(bridge, args):
    def fn():
        pack = _resolve_pack(bridge, args.get("pack_ref"))
        return gate_tool.pack_verify(pack, bridge.bridge_pub)
    return bridge._log_call("pack_verify", args, fn)


def tool_gate_assertions_check(bridge, args):
    def fn():
        aset = _resolve_assertion_set(bridge, args.get("assertion_set_ref"))
        out = gate_tool.gate_assertions_check(aset)
        if not out["valid"]:
            raise gate_tool.GateRefusal(
                "ASSERTION_TYPE_UNKNOWN",
                f"unknown assertion types: {out['unknown_assertions']}")
        return out
    return bridge._log_call("gate_assertions_check", args, fn)


STANDALONE_TOOLS = {
    "pin_verify": tool_pin_verify,
    "pin_show": tool_pin_show,
    "pin_status": tool_pin_status,
    "gate_run": tool_gate_run,
    "pack_verify": tool_pack_verify,
    "gate_assertions_check": tool_gate_assertions_check,
}


# ------------------------------------------------------------- admin CLI
def _fx() -> Path:
    import os
    return Path(os.environ.get("ECLIPSE_PROVING_FIXTURES",
                               HERE / "fixtures"))


def _read_control():
    path = _fx() / "control.local.json"
    if path.exists():
        return json.loads(path.read_text()), path
    return {"bench_frozen": False, "revoked_mandates": [],
            "revoked_pins": []}, path


def _owner_seed() -> bytes:
    import os
    key_path = Path(os.environ.get(
        "ECLIPSE_PROVING_OWNER_KEY", _fx() / "owner_key.json"))
    return bytes.fromhex(json.loads(key_path.read_text())["seed_hex"])


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="bridge.py", description="Eclipse Proving owner/admin "
        "CLI (§6.2) — NOT an MCP surface.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("bench_freeze_set")
    p.add_argument("on_off", choices=["on", "off"])
    p = sub.add_parser("tier_arm")
    p.add_argument("--board", required=True)
    p.add_argument("--session", required=True)
    p.add_argument("--recovery-path-ref")
    p = sub.add_parser("lease_release")
    p.add_argument("--board", required=True)
    p.add_argument("--reason", default="owner")
    p = sub.add_parser("mandate_revoke")
    p.add_argument("--mandate", required=True)
    p = sub.add_parser("pack_export")
    p.add_argument("--pack", required=True)
    args = parser.parse_args(argv)

    control, control_path = _read_control()
    if args.cmd == "bench_freeze_set":
        control["bench_frozen"] = args.on_off == "on"
        control_path.write_text(json.dumps(control, indent=1))
        print(json.dumps({"bench_frozen": control["bench_frozen"]}))
    elif args.cmd == "mandate_revoke":
        if args.mandate not in control["revoked_mandates"]:
            control["revoked_mandates"].append(args.mandate)
        control_path.write_text(json.dumps(control, indent=1))
        print(json.dumps({"revoked": args.mandate,
                          "note": "live sessions freeze on next "
                                  "bridge start or in-process admin "
                                  "call; dead-man rule §5.1 applies"}))
    elif args.cmd == "lease_release":
        print(json.dumps({"board_id": args.board,
                          "note": "leases are process-held at P0; "
                                  "release via in-process "
                                  "admin_lease_release or restart"}))
    elif args.cmd == "tier_arm":
        import hashlib
        import receipts as _r
        arm = {"arm_id": "arm-" + hashlib.sha256(
            f"{args.board}|{args.session}".encode()).hexdigest()[:12],
            "board_id": args.board, "session_id": args.session,
            "armed_by": "owner (admin CLI, §6.2)",
            "armed_at": "2026-10-25T00:00:00+00:00",
            "expires_at": "2999-01-01T00:00:00+00:00",
            "capture_required": True,
            "recovery_path_ref": args.recovery_path_ref}
        arm["owner_signature"] = herald_sig.sign(
            _owner_seed(), _r.canon(arm).encode()).hex()
        arms_path = _fx() / "arms.local.json"
        arms = {"arms": []}
        if arms_path.exists():
            arms = json.loads(arms_path.read_text())
        arms["arms"] = [a for a in arms["arms"]
                        if a["arm_id"] != arm["arm_id"]] + [arm]
        arms_path.write_text(json.dumps(arms, indent=1))
        print(json.dumps({"arm_id": arm["arm_id"],
                          "board_id": args.board,
                          "session_id": args.session}))
    elif args.cmd == "pack_export":
        print(json.dumps({"pack": args.pack,
                          "note": "packs are process-held at P0; "
                                  "export via pack_verify/gate_run "
                                  "in-process or the session host"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


# Eclipse Proving MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
