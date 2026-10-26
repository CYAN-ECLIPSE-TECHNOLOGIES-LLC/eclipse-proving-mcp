#!/usr/bin/env python3
# Eclipse Proving MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# Eclipse Proving Gate (§8) — boot-evidence checker over sealed packs.

"""Eclipse Proving Gate — boot-evidence checker (spec §8).

Runs an assertion set against a SEALED evidence pack (never a live
board) -> BOOT_VERIFIED | BOOT_UNVERIFIED, every failing assertion
named. Assertion vocabulary is closed (§8.1); an unknown assertion
type refuses ASSERTION_TYPE_UNKNOWN — Gate never silently skips
an assertion it cannot evaluate (§8.2 tool 22). Verdicts inherit
the pack's target_class (§4.3) and are records stored beside packs,
never inside them (§9.5).
"""
import re

import receipts

GATE_VERSION = "proving-gate-1.0"

ASSERTION_TYPES = (
    "boot_banner", "register_eq", "memory_eq", "loaded_hash_eq",
    "console_contains", "console_not_contains", "power_state_eq",
    "receipt_chain_valid",
)


class GateRefusal(Exception):
    def __init__(self, code, detail=""):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def gate_assertions_check(assertion_set: dict) -> dict:
    """Tool 22 — validate assertion set vs closed vocabulary (§8.2)."""
    unknown = []
    assertions = assertion_set.get("assertions")
    if not isinstance(assertions, list):
        return {"valid": False, "unknown_assertions": [],
                "detail": "assertions must be a list"}
    for a in assertions:
        if not isinstance(a, dict) or a.get("type") not in ASSERTION_TYPES:
            unknown.append(a.get("type") if isinstance(a, dict)
                           else type(a).__name__)
    return {"valid": not unknown, "unknown_assertions": unknown,
            "set_id": assertion_set.get("set_id"),
            "assertion_count": len(assertions)}


def _eval_assertion(a: dict, pack: dict, bridge_pubkey: bytes):
    """(passed: bool, evidence_ref: str)."""
    ev = pack.get("evidence", {})
    kind = a["type"]
    if kind == "receipt_chain_valid":
        ok, _ = receipts.verify_pack(pack, bridge_pubkey)
        return ok, "receipts+seal"
    if kind == "boot_banner":
        return bool(re.search(a["pattern"], ev.get("console_text", ""))), \
            "evidence.console_text"
    if kind == "console_contains":
        return a["text"] in ev.get("console_text", ""), \
            "evidence.console_text"
    if kind == "console_not_contains":
        return a["text"] not in ev.get("console_text", ""), \
            "evidence.console_text"
    if kind == "register_eq":
        key = f"{a['target']}|{a['address']}"
        val = ev.get("registers", {}).get(key)
        if val is None:
            return False, f"evidence.registers[{key}] absent"
        mask = a.get("mask", 0xFFFFFFFF)
        return (val & mask) == (a["expected"] & mask), \
            f"evidence.registers[{key}]={val:#x}"
    if kind == "memory_eq":
        got = ev.get("memory_hashes", {}).get(a["address"])
        return got == a["expected_sha256"], \
            f"evidence.memory_hashes[{a['address']}]={got}"
    if kind == "loaded_hash_eq":
        hashes = [ld["artifact_sha256"] for ld in pack.get("loads", [])]
        return a["artifact_sha256"] in hashes, "pack.loads"
    if kind == "power_state_eq":
        return ev.get("power_state") == a["expected"], \
            "evidence.power_state"
    raise GateRefusal("ASSERTION_TYPE_UNKNOWN", kind)


def gate_run(pack: dict, assertion_set: dict, bridge_pubkey: bytes,
             at: str = "") -> dict:
    """Tool 20 — verdict over a sealed pack (§8.2)."""
    check = gate_assertions_check(assertion_set)
    if not check["valid"]:
        raise GateRefusal(
            "ASSERTION_TYPE_UNKNOWN",
            f"unknown assertion types: {check['unknown_assertions']}")
    ok, reason = receipts.verify_pack(pack, bridge_pubkey)
    per = []
    for a in assertion_set["assertions"]:
        if not ok and a["type"] != "receipt_chain_valid":
            per.append({"assertion": a, "result": "FAIL",
                        "evidence_ref": f"pack invalid: {reason}"})
            continue
        passed, ref = _eval_assertion(a, pack, bridge_pubkey)
        per.append({"assertion": a,
                    "result": "PASS" if passed else "FAIL",
                    "evidence_ref": ref})
    # receipt_chain_valid is structural — always evaluated (§8.1).
    if not any(a["type"] == "receipt_chain_valid"
               for a in assertion_set["assertions"]):
        passed, ref = _eval_assertion(
            {"type": "receipt_chain_valid"}, pack, bridge_pubkey)
        per.append({"assertion": {"type": "receipt_chain_valid"},
                    "result": "PASS" if passed else "FAIL",
                    "evidence_ref": ref})
    verdict = "BOOT_VERIFIED" if all(p["result"] == "PASS"
                                     for p in per) else "BOOT_UNVERIFIED"
    body = {"pack_id": pack.get("pack_id"),
            "set_id": assertion_set.get("set_id"),
            "verdict": verdict, "per_assertion": per,
            "pack_sha256": pack.get("seal", {}).get("pack_sha256"),
            "target_class": pack.get("target_class"),
            "gate_version": GATE_VERSION, "at": at}
    body["verdict_id"] = "verdict-" + receipts.sha(
        receipts.canon(body))[:16]
    body["sha256"] = receipts.sha(receipts.canon(body))
    return body


def pack_verify(pack: dict, bridge_pubkey: bytes) -> dict:
    """Tool 21 — offline structural verify (§8.2)."""
    ok, reason = receipts.verify_pack(pack, bridge_pubkey)
    return {"ok": ok,
            "verdict": "PACK_VALID" if ok else "PACK_INVALID",
            "reason": reason, "pack_id": pack.get("pack_id"),
            "target_class": pack.get("target_class")}


# Eclipse Proving MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
