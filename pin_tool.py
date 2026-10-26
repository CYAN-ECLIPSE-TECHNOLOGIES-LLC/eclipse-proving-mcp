#!/usr/bin/env python3
# Eclipse Proving MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# Eclipse Proving Pin (§7) — provenance verifier, offline runnable.

"""Eclipse Proving Pin — provenance verifier (spec §7).

Pin record (Herald-signed): {pin_id, artifact_sha256,
artifact_class, size_bytes, target_constraints, approver_identity,
approval_scope, issued_at, expires_at?, herald_signature}.

Load-path check order (§7.1) is exact; first failure stops:
  1 signature -> PIN_SIGNATURE_INVALID
  2 expiry/revocation -> PIN_EXPIRED / PIN_REVOKED
  3 bridge-computed artifact hash == pin -> ARTIFACT_PIN_MISMATCH
  4 class + size match pin -> ARTIFACT_PIN_MISMATCH
  5 actual target satisfies constraints -> TARGET_MISMATCH
  6 artifact inside session mandate pin set -> ARTIFACT_NOT_IN_MANDATE
pin_verify (tool 17) runs steps 1-4 offline, in third-party hands.
"""
import hashlib
from datetime import datetime, timezone

import herald_sig
from receipts import canon


class PinRefusal(Exception):
    def __init__(self, code, detail=""):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def signed_body(record: dict) -> dict:
    return {k: v for k, v in record.items() if k != "herald_signature"}


def verify_signature(record: dict, herald_pubkey: bytes) -> bool:
    try:
        sig = bytes.fromhex(record.get("herald_signature", ""))
    except (ValueError, AttributeError):
        return False
    return herald_sig.verify(herald_pubkey,
                             canon(signed_body(record)).encode(), sig)


def _parse(ts):
    if ts is None:
        return None
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def pin_state(record: dict, revoked_ids, now: datetime) -> str:
    if record.get("pin_id") in (revoked_ids or set()):
        return "revoked"
    exp = _parse(record.get("expires_at"))
    if exp is not None and now >= exp:
        return "expired"
    return "active"


def check_steps_1_to_4(record: dict, artifact_bytes: bytes,
                       artifact_class: str, herald_pubkey: bytes,
                       revoked_ids, now: datetime) -> str:
    """§7.1 steps 1-4. Returns the bridge-computed artifact sha."""
    if not verify_signature(record, herald_pubkey):
        raise PinRefusal("PIN_SIGNATURE_INVALID",
                         "Herald signature does not verify")
    state = pin_state(record, revoked_ids, now)
    if state == "expired":
        raise PinRefusal("PIN_EXPIRED", f"pin {record.get('pin_id')}")
    if state == "revoked":
        raise PinRefusal("PIN_REVOKED", f"pin {record.get('pin_id')}")
    digest = hashlib.sha256(artifact_bytes).hexdigest()
    if digest != record.get("artifact_sha256"):
        raise PinRefusal(
            "ARTIFACT_PIN_MISMATCH",
            "bridge-computed artifact hash differs from Herald pin "
            "(one-byte rule, §2.1); no override exists")
    if artifact_class != record.get("artifact_class") or \
            len(artifact_bytes) != record.get("size_bytes"):
        raise PinRefusal(
            "ARTIFACT_PIN_MISMATCH",
            "artifact class/size differ from pin fields")
    return digest


def check_target_constraints(record: dict, attested: dict):
    """§7.1 step 5: actual target vs pin constraints (§3.2.7)."""
    cons = record.get("target_constraints", {})
    if cons.get("device_part") and \
            cons["device_part"] != attested.get("device_part"):
        raise PinRefusal(
            "TARGET_MISMATCH",
            f"pin requires device_part {cons['device_part']}, "
            f"actual {attested.get('device_part')}")
    if cons.get("board_id") and \
            cons["board_id"] != attested.get("board_id"):
        raise PinRefusal(
            "TARGET_MISMATCH",
            f"pin requires board {cons['board_id']}, actual "
            f"{attested.get('board_id')}")
    rng = cons.get("board_rev_range")
    if rng and attested.get("board_rev") not in rng:
        raise PinRefusal(
            "TARGET_MISMATCH",
            f"board_rev {attested.get('board_rev')} outside pin "
            f"range {rng}")
    if cons.get("silicon_rev") and \
            cons["silicon_rev"] != attested.get("silicon_rev"):
        raise PinRefusal("TARGET_MISMATCH", "silicon_rev mismatch")


def pin_verify(artifact_bytes: bytes, artifact_class: str,
               record: dict, herald_pubkey: bytes, revoked_ids,
               now: datetime = None) -> dict:
    """Tool 17 — offline verify, steps 1-4 (§7.2)."""
    now = now or datetime.now(timezone.utc)
    try:
        digest = check_steps_1_to_4(record, artifact_bytes,
                                    artifact_class, herald_pubkey,
                                    revoked_ids, now)
    except PinRefusal as r:
        return {"ok": False, "verdict": r.code,
                "refusal": {"refusal_code": r.code, "detail": r.detail},
                "pin_id": record.get("pin_id")}
    return {"ok": True, "verdict": "PIN_VALID", "artifact_sha256": digest,
            "pin_id": record.get("pin_id"),
            "approver": record.get("approver_identity")}


def pin_show(record: dict, herald_pubkey: bytes) -> dict:
    """Tool 18 — record rendered with signature status + constraints."""
    return {"pin": record,
            "signature_status": "valid" if verify_signature(
                record, herald_pubkey) else "invalid",
            "target_constraints": record.get("target_constraints", {})}


def pin_status(record: dict, revoked_ids, now: datetime = None,
               revocation_source: str = "local revocation fixture "
               "(P0, §7.2)") -> dict:
    """Tool 19 — pin state (§7.2)."""
    now = now or datetime.now(timezone.utc)
    state = pin_state(record, revoked_ids, now)
    return {"pin_id": record.get("pin_id"), "state": state,
            "revocation_source": revocation_source if state == "revoked"
            else None}


# Eclipse Proving MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
