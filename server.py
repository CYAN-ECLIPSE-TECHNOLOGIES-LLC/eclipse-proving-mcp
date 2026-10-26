#!/usr/bin/env python3
# Eclipse Proving MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# Eclipse Proving Session — MCP server (stdio), 22 tools (§6).

"""Eclipse Proving Session — governed bench access for agents.

Spec: eclipse-proving-spec-20261025.md §6. The surface is exactly
22 tools: 16 Session (§6.1) + 3 Pin (§7.2) + 3 Gate (§8.2).
Deliberately ABSENT (§6.3/§6.4, enumeration-proven in tests):
fuse programming, PMIC/voltage config, boot-mode strap set, raw
Tcl/XSDB/shell escape hatches, wildcard board ops, admin verbs
(arm/freeze/revoke are owner admin-CLI acts, §6.2 — not tools).

Every call returns {ok, data | refusal, receipt_id}; every call —
success, refusal, or failure — appends a receipt (§11.2). Denied
parameter names (§6.4) refuse at this boundary, receipted, mapped
to their permanent codes where one exists. Target/evidence class
is honest everywhere: P0 targets are fixture + emulator; verdict
ceiling is CERTIFIED(simulator) (§13).

Transport: MCP over stdio (newline-delimited JSON-RPC 2.0),
stdlib only. Fixtures: $ECLIPSE_PROVING_FIXTURES or ./fixtures.
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

import bridge as bridge_mod  # noqa: E402
import proving_engine as engine  # noqa: E402
from proving_engine import Bridge, Refusal  # noqa: E402

BRIDGE = Bridge()

_S = {"type": "string"}
_I = {"type": "integer"}

# tool -> (description, properties, required). Session tools take
# session_id (§6 conventions); bench_discover/session_open do not.
TOOLS = {
    "bench_discover": (
        "Boards visible to a mandate (§6.1.1): {board_id, board_rev, "
        "target_class, state, strap_state}. Boards outside the "
        "mandate are not enumerated.",
        {"mandate_ref": _S}, ["mandate_ref"]),
    "session_open": (
        "Verify a Herald-signed mandate (signature, identity, "
        "revocation, time bounds, board, tiers — §9.1) and take the "
        "board lease -> {session_id, granted_tiers, lease_expires_at}.",
        {"mandate": {"type": ["string", "object"]}, "board_id": _S},
        ["mandate", "board_id"]),
    "session_status": (
        "Session state, board state, granted tiers, T3 arm state, "
        "write-window state, receipt count, pack status (§6.1.3).",
        {"session_id": _S}, ["session_id"]),
    "target_connect": (
        "Adapter connect + chain scan (T0) -> targets + chain_state.",
        {"session_id": _S, "board_id": _S}, ["session_id"]),
    "target_attest": (
        "State re-attestation (T0): programmed hashes, power state, "
        "console tail hash, target identity. Required before writes "
        "on an UNKNOWN board (§10.3).",
        {"session_id": _S, "board_id": _S}, ["session_id"]),
    "register_read": (
        "Register read (T0); out-of-map addresses refuse "
        "ADDRESS_OUT_OF_MAP.",
        {"session_id": _S, "target_id": _S, "address": _I,
         "width": _I}, ["session_id", "target_id", "address"]),
    "memory_read": (
        "Memory read (T0) -> {bytes_b64, sha256}; length capped per "
        "mandate caps.max_read_bytes.",
        {"session_id": _S, "target_id": _S, "address": _I,
         "length": _I}, ["session_id", "target_id", "address",
                         "length"]),
    "console_read": (
        "Serial console tail (T0, read-only) -> {text, truncated}.",
        {"session_id": _S, "board_id": _S, "since_receipt": _S,
         "max_bytes": _I}, ["session_id"]),
    "artifact_load": (
        "Pin-gated artifact load (T1): Herald pin check §7.1 in "
        "exact order, target-identity check, load inside a write "
        "window, readback. One byte off the pin refuses "
        "ARTIFACT_PIN_MISMATCH — no override exists (§2.1).",
        {"session_id": _S, "board_id": _S, "target_id": _S,
         "artifact_ref": _S, "pin_ref": _S, "artifact_class": _S},
        ["session_id", "board_id", "artifact_ref", "pin_ref",
         "artifact_class"]),
    "memory_write": (
        "Volatile memory write (T1) -> {written_sha256}; bounds + "
        "caps as reads.",
        {"session_id": _S, "target_id": _S, "address": _I,
         "bytes_b64": _S}, ["session_id", "target_id", "address",
                            "bytes_b64"]),
    "target_run": (
        "Run target from halt (T1) -> {core_state}.",
        {"session_id": _S, "target_id": _S},
        ["session_id", "target_id"]),
    "target_halt": (
        "Halt target (T1) -> {core_state, pc}.",
        {"session_id": _S, "target_id": _S},
        ["session_id", "target_id"]),
    "power_set": (
        "Power on|off|cycle (T2) — every act receipted before it is "
        "reported (§3.2.4). Dead-man bound: inside a write window "
        "refuses POWER_WINDOW_ACTIVE, never queued (§5.1).",
        {"session_id": _S, "board_id": _S, "state": _S},
        ["session_id", "board_id", "state"]),
    "target_reset": (
        "Target reset, system|core (T2) — receipted like power_set.",
        {"session_id": _S, "board_id": _S, "target_id": _S,
         "kind": _S}, ["session_id", "target_id"]),
    "persistent_write": (
        "Persistent boot-media write (T3): requires a live owner "
        "arm, a completed persistent_capture, and a recorded "
        "recovery path, then a pin-gated write + verify-readback "
        "(§5). The capture is a supporting op inside this tool's "
        "flow (§6.1 note), invoked via the bridge, not a 23rd tool.",
        {"session_id": _S, "board_id": _S, "media": _S,
         "artifact_ref": _S, "pin_ref": _S},
        ["session_id", "board_id", "media", "artifact_ref",
         "pin_ref"]),
    "session_close": (
        "Release the lease and seal the evidence pack -> {pack_id, "
        "pack_sha256, gate_ready}. A session that cannot seal does "
        "not report closed (§3.2.5).",
        {"session_id": _S, "reason": _S}, ["session_id"]),
    "pin_verify": (
        "Eclipse Proving Pin (§7.2): offline verify of an artifact "
        "against its Herald-signed pin, steps 1-4 -> PIN_VALID | "
        "refusal. Third-party runnable.",
        {"artifact_ref": _S, "pin_ref": _S},
        ["artifact_ref", "pin_ref"]),
    "pin_show": (
        "Pin record rendered with signature status + constraint set.",
        {"pin_ref": _S}, ["pin_ref"]),
    "pin_status": (
        "Pin state: active|expired|revoked + revocation source.",
        {"pin_ref": _S}, ["pin_ref"]),
    "gate_run": (
        "Eclipse Proving Gate (§8.2): assertion set over a SEALED "
        "pack -> BOOT_VERIFIED|BOOT_UNVERIFIED, failing assertions "
        "named, verdict inherits the pack's target_class.",
        {"pack_ref": _S, "assertion_set_ref": _S},
        ["pack_ref", "assertion_set_ref"]),
    "pack_verify": (
        "Offline structural verify of a sealed pack: receipt chain "
        "recompute, seal signature, gap/refusal completeness -> "
        "PACK_VALID | PACK_INVALID(reason).",
        {"pack_ref": _S}, ["pack_ref"]),
    "gate_assertions_check": (
        "Validate an assertion set against the closed §8.1 "
        "vocabulary; unknown types refuse ASSERTION_TYPE_UNKNOWN.",
        {"assertion_set_ref": _S}, ["assertion_set_ref"]),
}

SESSION_TOOLS = (
    "session_status", "target_connect", "target_attest",
    "register_read", "memory_read", "console_read", "artifact_load",
    "memory_write", "target_run", "target_halt", "power_set",
    "target_reset", "persistent_write", "session_close",
)

# §6.4 denylist — parameter semantics that must never appear.
# Mapped to the refusal that names the act where a permanent code
# exists (§3.1); raw-escape params refuse OP_NOT_IN_MANDATE (§3.2.3).
DENIED_PARAM_REFUSALS = {
    "voltage": "PERMANENT_REFUSED_PMIC",
    "pmic": "PERMANENT_REFUSED_PMIC",
    "voltage_set": "PERMANENT_REFUSED_PMIC",
    "set_voltage": "PERMANENT_REFUSED_PMIC",
    "fuse": "PERMANENT_REFUSED_FUSE",
    "efuse": "PERMANENT_REFUSED_FUSE",
    "strap_set": "BOOT_MODE_PHYSICAL",
    "tcl": "OP_NOT_IN_MANDATE",
    "script": "OP_NOT_IN_MANDATE",
    "command": "OP_NOT_IN_MANDATE",
    "shell": "OP_NOT_IN_MANDATE",
    "exec": "OP_NOT_IN_MANDATE",
    "xsdb": "OP_NOT_IN_MANDATE",
    "raw": "OP_NOT_IN_MANDATE",
}

# Names that must never resolve as tools (§6.3): fuzzed/permanent-op
# names refuse as unknown tools at the transport (H-11).
FORBIDDEN_TOOL_NAMES = {
    "fuse_program", "program_fuse", "efuse_program", "pmic_config",
    "voltage_set", "set_voltage", "strap_set", "boot_mode_set",
    "exec_tcl", "tcl", "xsdb_console", "shell", "raw_command",
    "tier_arm", "bench_freeze_set", "mandate_revoke", "lease_release",
    "pack_export", "persistent_capture",
}


def tool_list():
    return [{"name": name, "description": desc,
             "inputSchema": {"type": "object", "properties": props,
                             "required": required}}
            for name, (desc, props, required) in TOOLS.items()]


def _result(rid, payload, is_error=False):
    return {"jsonrpc": "2.0", "id": rid, "result": {
        "content": [{"type": "text", "text": json.dumps(payload)}],
        "isError": is_error}}


def _boundary_refusal(rid, tool, args, code, detail):
    out = BRIDGE._log_call(tool, args, lambda: (_ for _ in ()).throw(
        Refusal(code, detail)))
    return _result(rid, out, is_error=True)


def dispatch(tool, args):
    """Route a validated call. Session ops go through the engine's
    receipted dispatch; Pin/Gate are standalone (§7.2/§8.2)."""
    if tool == "bench_discover":
        return BRIDGE.bench_discover(args)
    if tool == "session_open":
        return BRIDGE.session_open(args)
    if tool in SESSION_TOOLS:
        return BRIDGE.call_session_op(tool, args)
    return bridge_mod.STANDALONE_TOOLS[tool](BRIDGE, args)


def _envelope_error(rid, code, message):
    return {"jsonrpc": "2.0", "id": rid,
            "error": {"code": code, "message": message}}


def handle(req: dict):
    # Envelope guards (bench D-3 fix, house hygiene): every
    # wrong-shape envelope input — non-object request, non-string
    # method, params as str/int/list, tool name as list/dict —
    # refuses with a structured -32600/-32602 and the server NEVER
    # dies; no exception escapes handle(), and the bridge receipt /
    # audit chains are untouched by envelope refusals.
    if not isinstance(req, dict):
        return _envelope_error(
            None, -32600,
            "invalid request: the JSON-RPC envelope must be an "
            "object; refused, server alive")
    method, rid = req.get("method", ""), req.get("id")
    if not isinstance(method, str):
        return _envelope_error(
            rid, -32600,
            "invalid request: method must be a string; refused, "
            "server alive")
    if method == "initialize":
        init_params = req.get("params")
        protocol = init_params.get("protocolVersion",
                                   "2025-03-26") \
            if isinstance(init_params, dict) else "2025-03-26"
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": protocol,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "eclipse-proving",
                           "version": "0.1.0"}}}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": rid, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid,
                "result": {"tools": tool_list()}}
    if method == "tools/call":
        params = req.get("params")
        if not isinstance(params, dict):
            return _envelope_error(
                rid, -32602,
                f"invalid params: params must be an object (got "
                f"{type(params).__name__}); refused, server alive")
        name = params.get("name", "")
        if not isinstance(name, str):
            return _envelope_error(
                rid, -32602,
                f"invalid params: tool name must be a string (got "
                f"{type(name).__name__}); refused, server alive")
        args = params.get("arguments", {})
        if name in FORBIDDEN_TOOL_NAMES or name not in TOOLS:
            return {"jsonrpc": "2.0", "id": rid, "error": {
                "code": -32602,
                "message": f"unknown tool {name}: the Proving "
                           "surface is exactly the 22 tools of §6; "
                           "permanent ops and admin verbs do not "
                           "exist here (§6.3/§6.4)"}}
        try:
            engine.require_container_param(args, "arguments", "object")
        except engine.ToolError as e:
            return {"jsonrpc": "2.0", "id": rid, "error": {
                "code": -32602, "message": str(e)}}
        _, props, _ = TOOLS[name]
        for key in args:
            if key in DENIED_PARAM_REFUSALS:
                return _boundary_refusal(
                    rid, name, args, DENIED_PARAM_REFUSALS[key],
                    f"parameter {key!r} is on the §6.4 denylist; "
                    "the act it names does not exist in this surface")
            if key not in props:
                return _boundary_refusal(
                    rid, name, args, "ARGUMENT_UNKNOWN",
                    f"parameter {key!r} is not in the {name} schema; "
                    "refused at the boundary, receipted (§6.4)")
            # Reference-type guard at the boundary: a schema "string"
            # param arriving as a non-string refuses BY NAME before
            # any lookup — never a downstream TypeError from a dict
            # key or an unhashable ref (house fuzz lesson).
            if props[key].get("type") == "string" and \
                    not isinstance(args[key], str):
                return _boundary_refusal(
                    rid, name, args, "ARGUMENT_TYPE",
                    f"parameter {key!r} must be a string (got "
                    f"{type(args[key]).__name__}); refused by name, "
                    "never coerced")
        out = dispatch(name, args)
        return _result(rid, out, is_error=not out.get("ok", False))
    return {"jsonrpc": "2.0", "id": rid, "error": {
        "code": -32601, "message": f"method not found: {method}"}}


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        # Last-resort envelope guard: handle() refuses every known
        # wrong shape itself; if anything unforeseen still raises,
        # the stdio server answers -32600 and stays alive (D-3).
        try:
            resp = handle(req)
        except Exception:
            resp = _envelope_error(
                req.get("id") if isinstance(req, dict) else None,
                -32600,
                "invalid request envelope; refused, server alive")
        req_id = req.get("id") if isinstance(req, dict) else None
        if resp is not None and (req_id is not None or
                                 not isinstance(req, dict)):
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()


# Eclipse Proving MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
