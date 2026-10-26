#!/usr/bin/env python3
# Eclipse Proving MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# Hash-chained receipts + Blackbox-form evidence pack seal (§11).

"""Receipt chain + evidence pack sealing (spec §11).

Per operation: Receipt {receipt_id, session_id, seq, op summary +
params_hash, result/refusal, prev_receipt_sha256, receipt_sha256
= SHA256(prev || canonical(op record)), at}. Genesis receipt binds
{mandate_id, board_id, target_class, opened_at}. The seal binds
chain head + pack hash and is bridge-signed (Ed25519, herald_sig).
pack_verify (gate_tool) recomputes this chain offline — any
mutation, deletion, or reordering breaks verification.
"""
import hashlib
import json

import herald_sig


def canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


GENESIS_PREV = "0" * 64


class ReceiptChain:
    """Append-only hash chain. Bridge-authored; agent never writes."""

    def __init__(self, session_id: str, genesis: dict):
        self.session_id = session_id
        self.receipts = []
        self.append("session_genesis", genesis,
                    result="ok", op_summary="session_open genesis")

    def append(self, op_id: str, record: dict, result: str,
               op_summary: str, refusal_code=None, at: str = ""):
        # Deep-copy via canonical JSON: the caller's record objects
        # keep mutating after the receipt is hashed (op records gain
        # receipt_id, packs gain seals); the chain must hash the
        # record AS APPENDED or offline recompute would diverge.
        record = json.loads(canon(record))
        prev = self.receipts[-1]["receipt_sha256"] if self.receipts \
            else GENESIS_PREV
        body = {
            "session_id": self.session_id,
            "seq": len(self.receipts),
            "op_id": op_id,
            "op_summary": op_summary,
            "params_hash": sha(canon(record.get("params", {}))),
            "result": result,
            "refusal_code": refusal_code,
            "record": record,
            "prev_receipt_sha256": prev,
            "at": at,
        }
        body["receipt_sha256"] = sha(prev + "|" + canon(
            {k: v for k, v in body.items() if k != "receipt_sha256"}))
        body["receipt_id"] = "rcpt-" + body["receipt_sha256"][:16]
        self.receipts.append(body)
        return body

    @property
    def head(self) -> str:
        return self.receipts[-1]["receipt_sha256"]


def verify_chain(receipts) -> bool:
    """Recompute the full chain; False on any tamper/reorder/gap."""
    prev = GENESIS_PREV
    for i, r in enumerate(receipts):
        if r.get("seq") != i or r.get("prev_receipt_sha256") != prev:
            return False
        # receipt_id is derived FROM receipt_sha256 after hashing,
        # so it is excluded from the recompute exactly as at append.
        expect = sha(prev + "|" + canon(
            {k: v for k, v in r.items()
             if k not in ("receipt_sha256", "receipt_id")}))
        if expect != r.get("receipt_sha256"):
            return False
        if r.get("receipt_id") != "rcpt-" + expect[:16]:
            return False
        prev = expect
    return True


def seal_pack(pack_body: dict, bridge_seed: bytes) -> dict:
    """Bind chain head + pack hash under the bridge signature."""
    # Deep-copy: session lists keep growing after the seal (the
    # session itself is closed by a later state write); the sealed
    # pack must be a frozen snapshot or verify would diverge.
    pack = json.loads(canon(pack_body))
    pack_hash = sha(canon(pack))
    seal = {
        "chain_head_sha256": pack["receipts"][-1]["receipt_sha256"]
        if pack.get("receipts") else GENESIS_PREV,
        "pack_sha256": pack_hash,
    }
    seal["bridge_signature"] = herald_sig.sign(
        bridge_seed, canon(seal).encode()).hex()
    pack["seal"] = seal
    return pack


def verify_pack(pack: dict, bridge_pubkey: bytes):
    """(ok, reason). Structural verify, offline (spec §8.2/§11.2)."""
    if not isinstance(pack, dict):
        return False, "pack is not an object"
    for field in ("pack_id", "session", "mandate", "target_class",
                  "board", "targets", "operations", "refusals",
                  "receipts", "power_acts", "loads", "captures",
                  "gap_records", "strap_state", "opened_at",
                  "sealed_at", "seal"):
        if field not in pack:
            return False, f"mandatory pack section missing: {field}"
    if pack["target_class"] not in ("fixture", "emulator", "bench"):
        return False, "target_class missing or not a §4.3 class"
    if not verify_chain(pack["receipts"]):
        return False, "receipt chain recompute failed"
    seal = pack["seal"]
    body = {k: v for k, v in pack.items() if k != "seal"}
    if sha(canon(body)) != seal.get("pack_sha256"):
        return False, "pack hash mismatch (content tampered)"
    if pack["receipts"] and seal.get("chain_head_sha256") != \
            pack["receipts"][-1]["receipt_sha256"]:
        return False, "seal chain head mismatch"
    seal_body = {"chain_head_sha256": seal["chain_head_sha256"],
                 "pack_sha256": seal["pack_sha256"]}
    try:
        sig = bytes.fromhex(seal.get("bridge_signature", ""))
    except ValueError:
        return False, "seal signature not hex"
    if not herald_sig.verify(bridge_pubkey, canon(seal_body).encode(),
                             sig):
        return False, "seal signature invalid"
    # Refusal completeness: every refusal in ops appears in refusals[].
    op_refusals = [op["op_id"] for op in pack["operations"]
                   if op.get("result") == "refusal"]
    listed = {r["op_id"] for r in pack["refusals"]}
    if any(o not in listed for o in op_refusals):
        return False, "refusal missing from pack refusals[]"
    return True, "PACK_VALID"


# Eclipse Proving MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
