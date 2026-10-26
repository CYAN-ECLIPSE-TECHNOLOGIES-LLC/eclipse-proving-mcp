#!/usr/bin/env python3
# Eclipse Proving MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# Proving engine — mandate/lease/tier/refusal logic, bridge core.

"""Eclipse Proving engine — governed bench access for agents.

Spec: eclipse-proving-spec-20261025.md. Authority = agent_identity
x board_identity x op_class x artifact_hash, all four bound in one
Herald-signed mandate, all four checked per operation at the bridge
(§2.1). One-byte rule: an artifact differing by one byte from its
Herald-pinned hash refuses ARTIFACT_PIN_MISMATCH; no override
parameter exists anywhere in the surface.

House reference guards pre-installed (program law): coerce_int_param,
parse_time, require_container_param (reference-type guard), and the
verified-approval pattern — every T3 verb verifies its owner arm
record's signature + fields at use time, never trusting a flag.

Permanent refusals (§3.1) have NO tool and NO adapter call site:
fuse programming (PERMANENT_REFUSED_FUSE), PMIC/voltage config
(PERMANENT_REFUSED_PMIC), boot-mode strap set (BOOT_MODE_PHYSICAL —
strap state is read-only, T0). Denied parameter names (§6.4) refuse
at the schema boundary, receipted.

Dead-man rule (§5.1): revocation/freeze/expiry freeze NEW ops only;
power is never cut inside an active write window; a power op inside
a window refuses POWER_WINDOW_ACTIVE and is never queued.
"""
import base64
import hashlib
import json
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

import gate_tool
import herald_sig
import pin_tool
import receipts
from adapters import make_adapter
from adapters.base import AdapterError, in_map

HERE = Path(__file__).parent
FIXTURES = Path(os.environ.get("ECLIPSE_PROVING_FIXTURES",
                               HERE / "fixtures"))
ENGINE_VERSION = "proving-1.0"

# §9.4 refusal enum — VERBATIM, closed. New codes require spec amendment.
REFUSALS = (
    "NO_MANDATE", "MANDATE_SIGNATURE_INVALID", "MANDATE_EXPIRED",
    "MANDATE_REVOKED", "AGENT_IDENTITY_UNVERIFIED",
    "BOARD_NOT_IN_MANDATE", "BOARD_WILDCARD_REFUSED",
    "OP_NOT_IN_MANDATE", "TIER_NOT_GRANTED", "TIER_NOT_ARMED",
    "CAP_EXCEEDED", "SESSION_FROZEN", "BENCH_FROZEN",
    "LEASE_HELD", "LEASE_EXPIRED", "BOARD_STATE_UNKNOWN",
    "REATTESTATION_REQUIRED", "FOREIGN_CLIENT_ATTACHED",
    "ADDRESS_OUT_OF_MAP",
    "ARTIFACT_PIN_MISMATCH", "TARGET_MISMATCH", "NO_PIN",
    "PIN_SIGNATURE_INVALID", "PIN_EXPIRED", "PIN_REVOKED",
    "ARTIFACT_NOT_IN_MANDATE",
    "POWER_WINDOW_ACTIVE", "PREWRITE_CAPTURE_REQUIRED",
    "PREWRITE_CAPTURE_FAILED", "RECOVERY_PATH_UNRECORDED",
    "BOOT_MODE_PHYSICAL", "PERMANENT_REFUSED_FUSE",
    "PERMANENT_REFUSED_PMIC",
    "EVIDENCE_PACK_FAILURE", "ASSERTION_TYPE_UNKNOWN",
)
PERMANENT_REFUSALS = ("BOOT_MODE_PHYSICAL", "PERMANENT_REFUSED_FUSE",
                      "PERMANENT_REFUSED_PMIC")

# §6.4 denylist: parameter names that must never appear on any tool.
DENIED_PARAMS = ("tcl", "script", "command", "shell", "voltage",
                 "fuse", "strap_set", "raw", "exec", "xsdb",
                 "pmic", "voltage_set", "efuse")
TIERS = ("T0", "T1", "T2", "T3")
WRITE_TIERS = ("T1", "T3")


class ToolError(Exception):
    pass


class Refusal(Exception):
    """Named product refusal (§9.4 shape), always receipted."""

    def __init__(self, code, detail=""):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


# ------------------------------------------------------- reference guards
_INT_SHAPED_RE = re.compile(r"^[+-]?\d+$")
_OFFSET_RE = re.compile(r"(Z|[+-]\d{2}:?\d{2})$")


def coerce_int_param(value, name, refusal):
    """House reference guard: real ints, int-shaped strings, and
    integral floats pass; bools and everything else refuse BY NAME
    — never a bare int() crash."""
    if isinstance(value, bool):
        raise ToolError(f"{refusal}: {name} must be an integer, "
                        "not a boolean")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and _INT_SHAPED_RE.match(value.strip()):
        return int(value.strip())
    if isinstance(value, float) and value.is_integer():
        return int(value)
    raise ToolError(f"{refusal}: {name} must be an integer (got "
                    f"{type(value).__name__}); refused by name, "
                    "never coerced into a raw internal error")


def parse_time(value, field="time"):
    """House reference guard: ISO-8601 only with an explicit offset;
    offset-less timestamps refuse BY NAME — never guessed."""
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ToolError(f"PARSE_TIME_NO_OFFSET: {field} carries "
                            "no UTC offset; never assumed UTC")
        return value.astimezone(timezone.utc)
    if not isinstance(value, str) or not value.strip():
        raise ToolError(f"PARSE_TIME_INVALID: {field} must be an "
                        "ISO-8601 timestamp string with an offset")
    text = value.strip()
    if not _OFFSET_RE.search(text):
        raise ToolError(f"PARSE_TIME_NO_OFFSET: {field}={text!r} has "
                        "no UTC offset; timestamps are never guessed")
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise ToolError(f"PARSE_TIME_INVALID: {field}={text!r} is "
                        "not a valid ISO-8601 timestamp") from None
    if dt.tzinfo is None:
        raise ToolError(f"PARSE_TIME_NO_OFFSET: {field}={text!r}")
    return dt.astimezone(timezone.utc)


def require_container_param(value, name, expected):
    """Reference-type guard: a structured param must arrive as the
    container its schema declares ('object'->dict, 'array'->list);
    malformed containers refuse BY NAME at the boundary, pre-gate,
    pre-call — never coerced, never a downstream AttributeError."""
    ok = isinstance(value, dict) if expected == "object" \
        else isinstance(value, list)
    if not ok:
        raise ToolError(
            f"CONTAINER_TYPE_INVALID: {name} must be an {expected} "
            f"(got {type(value).__name__}); refused by name, never "
            "coerced into a raw internal error")
    return value


def require_reference(value, name):
    """Reference-type guard for record refs (mandate/pin/pack): a ref
    is a string id or the record object itself; anything else (int,
    list, bool) refuses BY NAME before any lookup happens."""
    if isinstance(value, (str, dict)):
        return value
    raise ToolError(
        f"REFERENCE_TYPE_INVALID: {name} must be a string ref or a "
        f"record object (got {type(value).__name__}); refused by "
        "name, never coerced")


def now_iso(dt=None) -> str:
    return (dt or datetime.now(timezone.utc)).replace(
        microsecond=0).isoformat()


def _uid(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def _load_json(path):
    return json.loads(Path(path).read_text())


# ------------------------------------------------------------------ bridge
class Bridge:
    """The Proving bridge (§4.1): sole client path agent->target.
    Holds registry, adapters, sessions, leases, packs, arms."""

    def __init__(self, fixtures_dir=None, clock=None):
        self.fx = Path(fixtures_dir) if fixtures_dir else FIXTURES
        self.clock = clock  # callable -> datetime, test-injectable
        keys = _load_json(self.fx / "keys.json")
        self.herald_pub = bytes.fromhex(keys["herald_pubkey"])
        self.bridge_pub = bytes.fromhex(keys["bridge_pubkey"])
        self.bridge_seed = bytes.fromhex(keys["bridge_seed"])
        self.owner_pub = bytes.fromhex(keys["owner_pubkey"])
        self.known_agents = set(keys.get("known_agents", []))
        self.registry = {b["board_id"]: b for b in
                         _load_json(self.fx / "registry.json")["boards"]}
        self.mandates = {m["mandate_id"]: m for m in
                         _load_json(self.fx / "mandates.json")["mandates"]}
        self.pins = {p["pin_id"]: p for p in
                     _load_json(self.fx / "pins.json")["pins"]}
        self.assertion_sets = {a["set_id"]: a for a in _load_json(
            self.fx / "assertion_sets.json")["sets"]}
        self.artifact_index = _load_json(
            self.fx / "artifacts.json")["artifacts"]
        revoc = _load_json(self.fx / "revocations.json")
        self.revoked_mandates = set(revoc.get("mandates", []))
        self.revoked_pins = set(revoc.get("pins", []))
        self.adapters = {}
        self.board_states = {}    # board_id -> §10.3 state, bridge-held
        self.sessions = {}
        self.leases = {}          # board_id -> lease record
        self.packs = {}           # pack_id -> sealed pack
        self.arms = {}            # arm_id -> arm record
        self.bench_frozen = False
        self.usage = {}           # mandate_id -> counters
        self.captures_store = {}  # capture_id -> image bytes
        self._lock = threading.RLock()
        self.bridge_log = receipts.ReceiptChain(
            "bridge-ops", {"scope": "bridge pre-session + standalone "
                           "tool receipts (§11.2)"})
        # Fault-injection hooks for the hostile bench (§13.3 H-12).
        self.inject_evidence_failure = False
        self.inject_seal_failure = False
        self.inject_capture_failure = False
        # Owner control plane (§6.2): the admin CLI writes
        # control.local.json / arms.local.json beside the fixtures;
        # a bridge process picks them up at start. In-process admin
        # methods below serve the same acts inside one process.
        control_path = self.fx / "control.local.json"
        if control_path.exists():
            control = _load_json(control_path)
            self.bench_frozen = bool(control.get("bench_frozen",
                                                 self.bench_frozen))
            self.revoked_mandates |= set(control.get(
                "revoked_mandates", []))
            self.revoked_pins |= set(control.get("revoked_pins", []))
        arms_path = self.fx / "arms.local.json"
        if arms_path.exists():
            for arm in _load_json(arms_path).get("arms", []):
                self.arms[arm["arm_id"]] = arm

    # -- time / stores ------------------------------------------------
    def now(self):
        return self.clock() if self.clock else \
            datetime.now(timezone.utc)

    def artifact_bytes(self, artifact_ref):
        if not isinstance(artifact_ref, str):
            return None, None
        meta = self.artifact_index.get(artifact_ref)
        if meta is None:
            return None, None
        return (self.fx / "artifacts" / meta["file"]).read_bytes(), meta

    def adapter_for(self, board_id):
        if board_id not in self.adapters:
            self.adapters[board_id] = make_adapter(
                self.registry[board_id])
        return self.adapters[board_id]

    # -- class integrity (§4.2 — bench D-1 fix) -------------------------
    def _check_class_integrity(self, board):
        """Pack target_class DERIVES from the adapter's declared
        class and is cross-checked against the registry entry at
        session_open, at connect, and at seal. A registry/adapter
        mismatch is a structured refusal and no pack seals: class
        cannot be upgraded (or downgraded) by config, flag, or
        session parameter (§4.2/§3.2.8). The declared class is a
        type-level attribute, read off a fresh adapter instance."""
        declared = make_adapter(board).target_class
        registry_class = board.get("target_class")
        if declared != registry_class:
            raise Refusal(
                "TARGET_MISMATCH",
                f"target_class mismatch: registry entry for "
                f"{board.get('board_id')} says {registry_class!r} "
                f"but the adapter declares {declared!r}; the pack "
                "class is the adapter-declared class and cannot be "
                "relabeled by config (§4.2)")
        return declared

    # -- time expiry (§5.1/§10.2 — bench D-2 fix) -----------------------
    def _check_time_expiry(self, session):
        """Per-op expiry, checked on EVERY operation, never only at
        session_open and never via a manual helper: clock past the
        mandate's expires_at -> MANDATE_EXPIRED; clock past the
        lease's expires_at -> LEASE_EXPIRED (lease transitions via
        expire_lease: HELD -> EXPIRED, board -> UNKNOWN if it was
        ATTESTED). Mandate is checked first so a mandate that
        expires at the same instant as its lease names the mandate.
        Sealed/dropped sessions are terminal and skip the check."""
        if session["state"] in ("SEALED", "DROPPED"):
            return
        now = self.now()
        bounds = session["mandate"].get("session_bounds", {})
        exp = parse_time(bounds.get("expires_at"),
                         "mandate.session_bounds.expires_at")
        if exp and now >= exp:
            raise Refusal("MANDATE_EXPIRED",
                          f"mandate expired at "
                          f"{bounds.get('expires_at')}; expiry "
                          "freezes new operations (§5.1)")
        lease = self.leases.get(session["board_id"])
        if lease and lease.get("session_id") == \
                session["session_id"] and lease.get("state") == "held":
            lexp = parse_time(lease.get("expires_at"),
                              "lease.expires_at")
            if lexp and now >= lexp:
                self.expire_lease(session["board_id"])
                raise Refusal("LEASE_EXPIRED",
                              f"lease expired at "
                              f"{lease.get('expires_at')} (§10.2)")

    # -- verified-approval pattern ------------------------------------
    def verify_signed_record(self, record, pubkey, sig_field):
        """Verified-approval pattern: a presented record (mandate,
        pin, arm) is trusted only after its Herald/owner signature
        verifies over the canonical unsigned body — at use time,
        every time, never cached from presentation."""
        body = {k: v for k, v in record.items() if k != sig_field}
        try:
            sig = bytes.fromhex(record.get(sig_field, ""))
        except (ValueError, AttributeError):
            return False
        return herald_sig.verify(pubkey, receipts.canon(body).encode(),
                                 sig)

    # -- mandate validation (§9.1, in order) ---------------------------
    def validate_mandate(self, mandate, board_id):
        if not self.verify_signed_record(
                mandate, self.herald_pub, "herald_signature"):
            raise Refusal("MANDATE_SIGNATURE_INVALID",
                          "Herald signature does not verify")
        if mandate.get("agent_identity") not in self.known_agents:
            raise Refusal("AGENT_IDENTITY_UNVERIFIED",
                          "agent identity is not a known Herald card")
        if mandate.get("mandate_id") in self.revoked_mandates:
            raise Refusal("MANDATE_REVOKED", mandate.get("mandate_id"))
        now = self.now()
        bounds = mandate.get("session_bounds", {})
        nb = parse_time(bounds.get("not_before"), "not_before")
        exp = parse_time(bounds.get("expires_at"), "expires_at")
        if nb and now < nb:
            raise Refusal("MANDATE_EXPIRED", "mandate not yet in bounds")
        if exp and now >= exp:
            raise Refusal("MANDATE_EXPIRED",
                          f"expired at {bounds.get('expires_at')}")
        entry = next((b for b in mandate.get("boards", [])
                      if b.get("board_id") == board_id), None)
        if entry is None:
            raise Refusal("BOARD_NOT_IN_MANDATE",
                          f"board {board_id} not named in mandate")
        if not entry.get("tiers"):
            raise Refusal("TIER_NOT_GRANTED",
                          "mandate grants no tier on this board")
        return entry

    def resolve_mandate(self, ref):
        require_reference(ref, "mandate")
        if isinstance(ref, dict):
            return ref
        mandate = self.mandates.get(ref)
        if mandate is None:
            raise Refusal("NO_MANDATE", f"unknown mandate ref {ref}")
        return mandate

    def resolve_pin(self, ref):
        require_reference(ref, "pin_ref")
        if isinstance(ref, dict):
            return ref
        pin = self.pins.get(ref)
        if pin is None:
            raise Refusal("NO_PIN", f"unknown pin ref {ref}")
        return pin

    # -- receipt / op recording ----------------------------------------
    def _append_op(self, session, tool, tier, board_id, target_id,
                   params, result, code, detail, started,
                   write_window=False, op_id=None):
        """Append the operation record + chain receipt (§11.2)."""
        op = {"op_id": op_id or _uid("op"),
              "session_id": session["session_id"],
              "seq": len(session["operations"]), "tool": tool,
              "tier": tier, "board_id": board_id,
              "target_id": target_id,
              "params_hash": receipts.sha(receipts.canon(params)),
              "params_summary": _summarize(params),
              "started_at": started, "finished_at": now_iso(self.now()),
              "write_window": write_window, "result": result,
              "refusal_code": code}
        receipt = session["chain"].append(
            op["op_id"], {"params": params, "op": op}, result,
            op_summary=f"{tool} {result}", refusal_code=code,
            at=op["finished_at"])
        op["receipt_id"] = receipt["receipt_id"]
        session["operations"].append(op)
        if tool in ("power_set", "target_reset") and result == "ok":
            # power_acts[] indexes ACTS (§11.1); a refused power op
            # is a refusal, not an act — it lives in refusals[].
            session["power_acts"].append(op["op_id"])
        if result == "refusal":
            session["refusals"].append({
                "refusal_code": code, "op_id": op["op_id"],
                "session_id": session["session_id"],
                "board_id": board_id, "tier_attempted": tier,
                "detail": (detail or "")[:300],
                "receipt_id": receipt["receipt_id"],
                "at": op["finished_at"]})
        return op, receipt

    def _record(self, session, tool, tier, board_id, target_id,
                params, fn, write_window=False):
        """Run fn() inside the receipt law: every call — success,
        refusal, or failure — appends an operation + a chain receipt
        (§11.2). Power acts are receipted before the result returns
        to the caller (§3.2.4): the receipt append precedes return."""
        started = now_iso(self.now())
        op_id = _uid("op")
        if write_window:
            session["write_window"] = {"op_id": op_id, "tool": tool}
        try:
            data = fn()
            result, code, pending = "ok", None, None
        except Refusal as r:
            data, result, code, pending = None, "refusal", r.code, r
        except pin_tool.PinRefusal as r:
            data, result, code = None, "refusal", r.code
            pending = Refusal(r.code, r.detail)
        except (ToolError, AdapterError) as e:
            data, result = None, "refusal"
            code = str(e).split(":")[0]
            pending = Refusal(code, str(e))
        finally:
            if write_window:
                session["write_window"] = None
        op, receipt = self._append_op(
            session, tool, tier, board_id, target_id, params, result,
            code, pending.detail if pending else None, started,
            write_window=write_window, op_id=op_id)
        if result == "refusal":
            return {"ok": False,
                    "refusal": {"refusal_code": code,
                                "detail": pending.detail,
                                "op_id": op["op_id"]},
                    "receipt_id": receipt["receipt_id"]}
        return {"ok": True, "data": data,
                "receipt_id": receipt["receipt_id"]}

    def _log_call(self, tool, params, fn):
        """Bridge-log receipting for pre-session + standalone tools."""
        op_id = _uid("op")
        try:
            data = fn()
            receipt = self.bridge_log.append(
                op_id, {"params": params}, "ok", f"{tool} ok",
                at=now_iso(self.now()))
            return {"ok": True, "data": data,
                    "receipt_id": receipt["receipt_id"]}
        except (Refusal, pin_tool.PinRefusal, gate_tool.GateRefusal,
                ToolError, AdapterError) as e:
            code = getattr(e, "code", str(e).split(":")[0])
            detail = getattr(e, "detail", str(e))
            receipt = self.bridge_log.append(
                op_id, {"params": params}, "refusal", f"{tool} refusal",
                refusal_code=code, at=now_iso(self.now()))
            return {"ok": False,
                    "refusal": {"refusal_code": code, "detail": detail,
                                "op_id": op_id},
                    "receipt_id": receipt["receipt_id"]}

    # -- common op gates -------------------------------------------------
    def _session(self, args):
        sid = args.get("session_id")
        session = self.sessions.get(sid) if isinstance(sid, str) \
            else None
        if session is None:
            raise Refusal("NO_MANDATE",
                          f"session {sid!r} is not open; no session, "
                          "no operation (§3.2.1)")
        return session

    def _set_board_state(self, session, state):
        session["board_state"] = state
        self.board_states[session["board_id"]] = state

    def _gate(self, session, tier, write_class=False):
        """Per-op gate order: time expiry -> frozen -> bench freeze
        -> evidence -> tier -> board state (§10.3/§10.4). Per op,
        never cached."""
        self._check_time_expiry(session)
        state = session["state"]
        if state == "EXPIRED":
            raise Refusal("LEASE_EXPIRED",
                          "the session's lease expired (H-5)")
        if state in ("SEALED", "DROPPED"):
            raise Refusal("SESSION_FROZEN",
                          f"session is {state}; no new operations")
        if state == "FROZEN" and tier != "T0":
            raise Refusal("SESSION_FROZEN",
                          "mandate revoked/expired mid-session; new "
                          "ops frozen, in-flight write untouched (§5.1)")
        if self.bench_frozen and tier in ("T1", "T2", "T3"):
            raise Refusal("BENCH_FROZEN",
                          "bench freeze is set; T0 reads continue (§10.4)")
        if state == "EVIDENCE_HALTED" and tier != "T0":
            raise Refusal("EVIDENCE_PACK_FAILURE",
                          "evidence halted; only reads + close are "
                          "legal (§11.4, §10.1)")
        if self.inject_evidence_failure and write_class:
            self.inject_evidence_failure = False
            session["state"] = "EVIDENCE_HALTED"
            raise Refusal("EVIDENCE_PACK_FAILURE",
                          "evidence pack write failed (fault "
                          "injected); session evidence-halted (§11.4)")
        if tier not in ("PRE",) and tier not in session["granted_tiers"]:
            raise Refusal("TIER_NOT_GRANTED",
                          f"{tier} not in granted tiers "
                          f"{session['granted_tiers']} for this board")
        board_state = session["board_state"]
        if tier in WRITE_TIERS:
            if board_state == "UNKNOWN":
                raise Refusal("REATTESTATION_REQUIRED",
                              "board is UNKNOWN; target_attest in "
                              "this session unlocks writes (§10.3, D-2)")
            if board_state != "ATTESTED":
                raise Refusal("BOARD_STATE_UNKNOWN",
                              f"board state {board_state}; writes "
                              "require ATTESTED")
        if tier == "T2":
            # §10.3: ATTESTED and not WRITING — but the WRITING case
            # must surface as POWER_WINDOW_ACTIVE from the op itself
            # (H-10), so only the UNKNOWN/state cases refuse here.
            if board_state == "UNKNOWN":
                raise Refusal("REATTESTATION_REQUIRED",
                              "board is UNKNOWN; attest before power")
            if board_state not in ("ATTESTED", "WRITING"):
                raise Refusal("BOARD_STATE_UNKNOWN",
                              f"board state {board_state}; power "
                              "requires ATTESTED")

    def _board_arg(self, session, args):
        board_id = args.get("board_id")
        if board_id is None:
            board_id = session["board_id"]
        if not isinstance(board_id, str) or board_id in ("*", ""):
            raise Refusal("BOARD_WILDCARD_REFUSED",
                          "every operation names exactly one board "
                          "(§3.2.6)")
        if board_id != session["board_id"]:
            raise Refusal("BOARD_NOT_IN_MANDATE",
                          "op names a board other than the session's")
        return board_id

    def _cap(self, session, kind, amount=1):
        caps = session["mandate"].get("caps", {})
        limit_key = {"loads": "max_loads", "power_cycles": "max_power_cycles",
                     "read_bytes": "max_read_bytes",
                     "write_bytes": "max_write_bytes"}[kind]
        limit = caps.get(limit_key)
        if limit is None:
            return
        used = self.usage.setdefault(
            session["mandate_id"], {}).get(kind, 0)
        if used + amount > limit:
            raise Refusal("CAP_EXCEEDED",
                          f"{limit_key}={limit} would be exceeded "
                          f"(used {used}, requested {amount})")
        self.usage[session["mandate_id"]][kind] = used + amount

    def _pin_check(self, session, board_id, artifact_ref, pin_ref,
                   artifact_class):
        """§7.1 exact sequence; first failure stops, receipted by
        the calling op. Returns (pin, artifact_bytes, digest)."""
        pin = self.resolve_pin(pin_ref) \
            if pin_ref is not None else None
        if pin is None:
            raise Refusal("NO_PIN", "no pin presented; no unpinned "
                          "loads, any class, any tier (§3.2.2)")
        data, meta = self.artifact_bytes(artifact_ref)
        if data is None:
            raise Refusal("ARTIFACT_PIN_MISMATCH",
                          f"artifact {artifact_ref!r} not present in "
                          "the artifact store; nothing can match a pin")
        digest = pin_tool.check_steps_1_to_4(
            pin, data, artifact_class, self.herald_pub,
            self.revoked_pins, self.now())
        adapter = self.adapter_for(board_id)
        pin_tool.check_target_constraints(pin, adapter.attest(board_id))
        if pin["pin_id"] not in session["mandate"].get("pins", []):
            raise Refusal("ARTIFACT_NOT_IN_MANDATE",
                          "pin is not inside the session mandate's "
                          "pin set (§7.1 step 6)")
        return pin, data, digest

    # ============================================================ tools
    def bench_discover(self, args):
        def fn():
            mandate = self.resolve_mandate(args.get("mandate_ref"))
            if not self.verify_signed_record(
                    mandate, self.herald_pub, "herald_signature"):
                raise Refusal("MANDATE_SIGNATURE_INVALID",
                              "Herald signature does not verify")
            if mandate.get("mandate_id") in self.revoked_mandates:
                raise Refusal("MANDATE_REVOKED", mandate["mandate_id"])
            out = []
            for entry in mandate.get("boards", []):
                board = self.registry.get(entry["board_id"])
                if board is None:
                    continue
                out.append({
                    "board_id": board["board_id"],
                    "board_rev": board["board_rev"],
                    "target_class": board["target_class"],
                    "state": self._board_state(entry["board_id"]),
                    "strap_state": board.get("strap_state"),
                    "device_part": board["device_part"],
                    "granted_tiers": entry.get("tiers", [])})
            return {"boards": out, "mandate_id": mandate["mandate_id"]}
        return self._log_call("bench_discover", args, fn)

    def _board_state(self, board_id):
        for s in self.sessions.values():
            if s["board_id"] == board_id and s["state"] not in (
                    "SEALED", "DROPPED"):
                return s["board_state"]
        return "IDLE"

    def session_open(self, args):
        def fn():
            board_id = args.get("board_id")
            if not isinstance(board_id, str) or board_id in ("*", ""):
                raise Refusal("BOARD_WILDCARD_REFUSED",
                              "session names exactly one board (§3.2.6)")
            mandate = self.resolve_mandate(args.get("mandate"))
            entry = self.validate_mandate(mandate, board_id)
            board = self.registry.get(board_id)
            if board is None:
                raise Refusal("BOARD_NOT_IN_MANDATE",
                              f"board {board_id} is not provisioned")
            # §4.2 class interlock at open: the session's class is
            # the ADAPTER-declared class; a registry entry relabeled
            # away from its adapter refuses here, before any lease.
            adapter_class = self._check_class_integrity(board)
            bounds = mandate.get("session_bounds", {})
            max_sessions = bounds.get("max_sessions")
            live = [s for s in self.sessions.values()
                    if s["mandate_id"] == mandate["mandate_id"]]
            if max_sessions is not None and \
                    len(live) >= int(max_sessions):
                raise Refusal("CAP_EXCEEDED",
                              "session_bounds.max_sessions reached")
            lease = self.leases.get(board_id)
            if lease and lease["state"] == "held":
                raise Refusal("LEASE_HELD",
                              f"board held by session "
                              f"{lease['session_id']} (§10.2)")
            session_id = _uid("sess")
            lease_id = _uid("lease")
            opened = self.now()
            duration = int(bounds.get("max_duration_s", 3600))
            from datetime import timedelta
            lease_exp = opened + timedelta(seconds=duration)
            session = {
                "session_id": session_id,
                "mandate_id": mandate["mandate_id"],
                "mandate": mandate,
                "agent_identity": mandate["agent_identity"],
                "principal": mandate.get("principal"),
                "board_id": board_id,
                "target_class": adapter_class,
                "granted_tiers": list(entry["tiers"]),
                "state": "OPEN",
                "board_state": "UNKNOWN" if self.board_states.get(
                    board_id) == "UNKNOWN" else "LEASED",
                "opened_at": now_iso(opened), "closed_at": None,
                "lease_id": lease_id, "pack_id": None,
                "operations": [], "refusals": [], "power_acts": [],
                "loads": [], "captures": [], "gap_records": [],
                "write_window": None, "attested_in_session": False,
                "evidence_memory": {}, "sealed_by": "session",
            }
            session["chain"] = receipts.ReceiptChain(session_id, {
                "mandate_id": mandate["mandate_id"],
                "board_id": board_id,
                "target_class": adapter_class,
                "session_opened_at": session["opened_at"]})
            self.sessions[session_id] = session
            self.leases[board_id] = {
                "lease_id": lease_id, "board_id": board_id,
                "session_id": session_id,
                "acquired_at": session["opened_at"],
                "expires_at": now_iso(lease_exp), "state": "held"}
            return {"session_id": session_id,
                    "granted_tiers": session["granted_tiers"],
                    "lease_expires_at": now_iso(lease_exp),
                    "target_class": adapter_class}
        return self._log_call("session_open", args, fn)

    # -- session op dispatch -------------------------------------------
    def call_session_op(self, tool, args):
        sid = args.get("session_id")
        session = self.sessions.get(sid) if isinstance(sid, str) \
            else None
        if session is None:
            return self._log_call(tool, args,
                                  lambda: (_ for _ in ()).throw(
                                      Refusal("NO_MANDATE",
                                              "session is not open")))
        if tool == "session_close":
            return self._close_with_receipt(session, args)
        handler = getattr(self, f"_t_{tool}")
        tier = {"session_status": "T0", "target_connect": "T0",
                "target_attest": "T0", "register_read": "T0",
                "memory_read": "T0", "console_read": "T0",
                "artifact_load": "T1", "memory_write": "T1",
                "target_run": "T1", "target_halt": "T1",
                "power_set": "T2", "target_reset": "T2",
                "persistent_capture": "T3", "persistent_write": "T3",
                "session_close": "PRE"}[tool]
        board_id = session["board_id"]
        write_window = tool in ("artifact_load", "memory_write",
                                "persistent_write")

        def run():
            if tool != "session_close":
                self._gate(session, tier,
                           write_class=tier in ("T1", "T3"))
            return handler(session, args)
        return self._record(session, tool, tier, board_id,
                            args.get("target_id"), _op_params(args),
                            run, write_window=write_window)

    # -- T0 ------------------------------------------------------------
    def _t_session_status(self, session, args):
        lease = self.leases.get(session["board_id"], {})
        arm = self._live_arm(session)
        return {"state": session["state"],
                "board_state": session["board_state"],
                "granted_tiers": session["granted_tiers"],
                "t3_arm_state": "armed" if arm else "not_armed",
                "write_window": session["write_window"],
                "receipt_count": len(session["chain"].receipts),
                "pack_status": "sealed" if session["pack_id"]
                else "open",
                "lease_state": lease.get("state"),
                "target_class": session["target_class"]}

    def _t_target_connect(self, session, args):
        board_id = self._board_arg(session, args)
        # §4.2 class interlock at connect: re-checked here, not
        # trusted from session_open — a registry relabeled after
        # open refuses at the connect that would bind the adapter.
        declared = self._check_class_integrity(
            self.registry[board_id])
        if declared != session["target_class"]:
            raise Refusal(
                "TARGET_MISMATCH",
                f"adapter declares {declared!r} but the session "
                f"was opened as {session['target_class']!r} (§4.2)")
        adapter = self.adapter_for(board_id)
        out = adapter.connect(board_id)
        scan = adapter.chain_scan()
        if session["state"] == "OPEN":
            session["state"] = "CONNECTED"
        if session["board_state"] != "UNKNOWN":
            self._set_board_state(session, "CONNECTED")
        return {"connect": out, "targets": scan["targets"],
                "chain_state": scan["chain_state"]}

    def _t_target_attest(self, session, args):
        board_id = self._board_arg(session, args)
        adapter = self.adapter_for(board_id)
        att = adapter.attest(board_id)
        att["strap_state"] = adapter.strap_state()
        self._set_board_state(session, "ATTESTED")
        session["attested_in_session"] = True
        if session["state"] in ("OPEN", "CONNECTED"):
            session["state"] = "ACTIVE"
        session["attestation"] = att
        return att

    def _coerce_addr(self, value):
        if isinstance(value, str) and value.strip().lower().startswith("0x"):
            return int(value.strip(), 16)
        return coerce_int_param(value, "address", "ADDRESS_FORMAT")

    def _t_register_read(self, session, args):
        address = self._coerce_addr(args.get("address"))
        width = coerce_int_param(args.get("width", 32), "width",
                                 "WIDTH_FORMAT")
        if width not in (8, 16, 32, 64):
            raise ToolError("WIDTH_FORMAT: width must be 8|16|32|64")
        if not in_map(address):
            raise Refusal("ADDRESS_OUT_OF_MAP",
                          f"{address:#x} outside the target map (§6.1)")
        adapter = self.adapter_for(session["board_id"])
        return adapter.register_read(args.get("target_id"), address,
                                     width)

    def _t_memory_read(self, session, args):
        address = self._coerce_addr(args.get("address"))
        length = coerce_int_param(args.get("length"), "length",
                                  "LENGTH_FORMAT")
        if length <= 0:
            raise ToolError("LENGTH_FORMAT: length must be positive")
        if not in_map(address) or not in_map(address + length - 1):
            raise Refusal("ADDRESS_OUT_OF_MAP",
                          "read range outside the target map")
        self._cap(session, "read_bytes", length)
        adapter = self.adapter_for(session["board_id"])
        out = adapter.memory_read(args.get("target_id"), address, length)
        session["evidence_memory"][hex(address)] = out["sha256"]
        return {"bytes_b64": base64.b64encode(out["bytes"]).decode(),
                "sha256": out["sha256"]}

    def _t_console_read(self, session, args):
        board_id = self._board_arg(session, args)
        max_bytes = coerce_int_param(args.get("max_bytes", 4096),
                                     "max_bytes", "MAX_BYTES_FORMAT")
        adapter = self.adapter_for(board_id)
        return adapter.console_read(max_bytes)

    # -- T1 ------------------------------------------------------------
    def _t_artifact_load(self, session, args):
        board_id = self._board_arg(session, args)
        artifact_class = args.get("artifact_class")
        if artifact_class not in ("bitstream", "elf"):
            raise ToolError("ARTIFACT_CLASS_INVALID: artifact_class "
                            "must be bitstream|elf")
        pin, data, digest = self._pin_check(
            session, board_id, args.get("artifact_ref"),
            args.get("pin_ref"), artifact_class)
        self._cap(session, "loads", 1)
        adapter = self.adapter_for(board_id)
        meta = self.artifact_index.get(args.get("artifact_ref"), {})
        window_op = (session.get("write_window") or {}).get("op_id")
        self._set_board_state(session, "WRITING")
        try:
            if artifact_class == "bitstream":
                out = adapter.load_bitstream(args.get("target_id"),
                                             data, meta)
            else:
                out = adapter.load_elf(args.get("target_id"), data, meta)
        finally:
            self._set_board_state(session, "ATTESTED")
        session["loads"].append({
            "pin_id": pin["pin_id"], "artifact_sha256": digest,
            "readback_sha256": out.get("readback_sha256"),
            "artifact_class": artifact_class,
            "target_id": args.get("target_id")})
        return {"loaded_sha256": out["loaded_sha256"],
                "readback_sha256": out.get("readback_sha256"),
                "semantics_note": out.get("semantics_note"),
                "window_receipts": [window_op] if window_op else []}

    def _t_memory_write(self, session, args):
        address = self._coerce_addr(args.get("address"))
        try:
            data = base64.b64decode(args.get("bytes_b64", ""),
                                    validate=True)
        except Exception:
            raise ToolError("BYTES_FORMAT: bytes_b64 is not valid "
                            "base64") from None
        if not in_map(address) or not in_map(address + len(data) - 1):
            raise Refusal("ADDRESS_OUT_OF_MAP",
                          "write range outside the target map")
        self._cap(session, "write_bytes", len(data))
        adapter = self.adapter_for(session["board_id"])
        self._set_board_state(session, "WRITING")
        try:
            return adapter.memory_write(args.get("target_id"), address,
                                        data)
        finally:
            self._set_board_state(session, "ATTESTED")

    def _t_target_run(self, session, args):
        adapter = self.adapter_for(session["board_id"])
        return adapter.run(args.get("target_id"))

    def _t_target_halt(self, session, args):
        adapter = self.adapter_for(session["board_id"])
        return adapter.halt(args.get("target_id"))

    # -- T2 ------------------------------------------------------------
    def _power_gate(self, session):
        if session.get("write_window"):
            raise Refusal(
                "POWER_WINDOW_ACTIVE",
                f"write window active ({session['write_window']}); "
                "power is never cut mid-write and the op is not "
                "queued (§5.1)")

    def _t_power_set(self, session, args):
        board_id = self._board_arg(session, args)
        self._power_gate(session)
        state = args.get("state")
        if state not in ("on", "off", "cycle"):
            raise ToolError("POWER_STATE_INVALID: state must be "
                            "on|off|cycle")
        if state == "cycle":
            self._cap(session, "power_cycles", 1)
        adapter = self.adapter_for(board_id)
        return adapter.power_set(state)

    def _t_target_reset(self, session, args):
        self._power_gate(session)
        kind = args.get("kind", "system")
        if kind not in ("system", "core"):
            raise ToolError("RESET_KIND_INVALID: kind must be "
                            "system|core")
        adapter = self.adapter_for(session["board_id"])
        out = adapter.reset(args.get("target_id"), kind)
        out["reset_receipt"] = "issued-in-pack (this op's receipt)"
        return out

    # -- T3 ------------------------------------------------------------
    def _live_arm(self, session):
        for arm in self.arms.values():
            if arm["session_id"] == session["session_id"] and \
                    arm["board_id"] == session["board_id"]:
                return arm
        return None

    def _verify_arm(self, session):
        """Verified-approval at use time: arm exists, binds this
        session+board, owner signature verifies, capture required."""
        arm = self._live_arm(session)
        if arm is None:
            raise Refusal("TIER_NOT_ARMED",
                          "T3 requires a live owner arm for this "
                          "board+session (§5.2); agents cannot arm")
        if not self.verify_signed_record(arm, self.owner_pub,
                                         "owner_signature"):
            raise Refusal("TIER_NOT_ARMED",
                          "arm record signature does not verify")
        if arm.get("capture_required") is not True:
            raise Refusal("TIER_NOT_ARMED",
                          "arm record lacks capture_required=true")
        exp = parse_time(arm.get("expires_at"), "arm.expires_at")
        if exp and self.now() >= exp:
            raise Refusal("TIER_NOT_ARMED", "arm expired")
        return arm

    def _media_entry(self, session, media_id):
        board = self.registry[session["board_id"]]
        return next((m for m in board.get("media", [])
                     if m["media_id"] == media_id), None)

    def _t_persistent_capture(self, session, args):
        self._verify_arm(session)
        media_id = args.get("media")
        entry = self._media_entry(session, media_id)
        if entry is None:
            raise ToolError(f"MEDIA_UNKNOWN: {media_id}")
        adapter = self.adapter_for(session["board_id"])
        image = adapter.persistent_read(media_id)
        capture_id = _uid("cap")
        digest = hashlib.sha256(image).hexdigest()
        self.captures_store[capture_id] = image
        record = {"capture_id": capture_id, "image_sha256": digest,
                  "media": media_id, "media_size": len(image),
                  "at": now_iso(self.now())}
        session["captures"].append(record)
        return record

    def _t_persistent_write(self, session, args):
        board_id = self._board_arg(session, args)
        arm = self._verify_arm(session)
        media_id = args.get("media")
        entry = self._media_entry(session, media_id)
        if entry is None:
            raise ToolError(f"MEDIA_UNKNOWN: {media_id}")
        capture = next((c for c in session["captures"]
                        if c["media"] == media_id), None)
        if capture is None:
            raise Refusal("PREWRITE_CAPTURE_REQUIRED",
                          "no completed persistent_capture for this "
                          "media in this session (§5 T3)")
        if self.inject_capture_failure or \
                hashlib.sha256(self.captures_store.get(
                    capture["capture_id"], b"")).hexdigest() != \
                capture["image_sha256"]:
            raise Refusal("PREWRITE_CAPTURE_FAILED",
                          "pre-write capture does not verify")
        if not entry.get("recovery_path_ref") and \
                not arm.get("recovery_path_ref"):
            raise Refusal("RECOVERY_PATH_UNRECORDED",
                          "no proven remote recovery path recorded "
                          "for this board/media (§5 T3)")
        pin, data, digest = self._pin_check(
            session, board_id, args.get("artifact_ref"),
            args.get("pin_ref"), "boot_image")
        adapter = self.adapter_for(board_id)
        self._set_board_state(session, "WRITING")
        try:
            out = adapter.persistent_write(media_id, data)
        finally:
            self._set_board_state(session, "ATTESTED")
        readback = adapter.persistent_read(media_id)
        expected = bytearray(self.captures_store[capture["capture_id"]])
        expected[:len(data)] = data
        if hashlib.sha256(bytes(expected)).hexdigest() != \
                hashlib.sha256(readback).hexdigest():
            raise Refusal("PREWRITE_CAPTURE_FAILED",
                          "post-write verify-readback mismatch")
        session["loads"].append({
            "pin_id": pin["pin_id"], "artifact_sha256": digest,
            "readback_sha256": out["written_sha256"],
            "artifact_class": "boot_image", "media": media_id})
        return {"written_sha256": out["written_sha256"],
                "capture_ref": capture["capture_id"]}

    # -- close / drop ----------------------------------------------------
    def _close_with_receipt(self, session, args):
        """session_close is receipted INTO its own pack (§11.1: every
        op in seq order) — so the close op + receipt append BEFORE
        the seal snapshot, unlike every other op. A session that
        cannot seal does not report closed (§3.2.5): the seal runs
        first in effect, and on seal failure the close op records
        the refusal and the session stays open."""
        started = now_iso(self.now())
        params = _op_params(args)
        try:
            if session["state"] not in ("OPEN", "CONNECTED", "ACTIVE",
                                        "FROZEN", "EVIDENCE_HALTED"):
                raise Refusal("SESSION_FROZEN",
                              f"cannot close from {session['state']}")
            if self.inject_seal_failure:
                raise Refusal("EVIDENCE_PACK_FAILURE",
                              "pack seal failed; a session that "
                              "cannot seal does not report closed "
                              "(§3.2.5)")
            # §4.2 seal interlock, pre-checked here so a class
            # mismatch records a receipted refusal close and seals
            # nothing (the seal path re-checks independently).
            board_now = self.registry.get(session["board_id"])
            if board_now is not None:
                declared_now = self._check_class_integrity(board_now)
                if declared_now != session["target_class"]:
                    raise Refusal(
                        "TARGET_MISMATCH",
                        f"adapter declares {declared_now!r} but "
                        f"the session carries "
                        f"{session['target_class']!r}; no pack "
                        "seals under a relabeled class (§4.2)")
        except Refusal as r:
            op, receipt = self._append_op(
                session, "session_close", "PRE", session["board_id"],
                None, params, "refusal", r.code, r.detail, started)
            return {"ok": False,
                    "refusal": {"refusal_code": r.code,
                                "detail": r.detail,
                                "op_id": op["op_id"]},
                    "receipt_id": receipt["receipt_id"]}
        op, receipt = self._append_op(
            session, "session_close", "PRE", session["board_id"], None,
            params, "ok", None, None, started)
        pack = self._seal_session(session, sealed_by="session")
        session["state"] = "SEALED"
        session["closed_at"] = now_iso(self.now())
        session["pack_id"] = pack["pack_id"]
        lease = self.leases.get(session["board_id"])
        if lease and lease["session_id"] == session["session_id"]:
            lease["state"] = "released"
        if session["board_state"] != "UNKNOWN":
            self._set_board_state(session, "IDLE")
        for arm_id in [a for a, r in self.arms.items()
                       if r["session_id"] == session["session_id"]]:
            del self.arms[arm_id]  # arm expires at session close (§5.2)
        return {"ok": True,
                "data": {"pack_id": pack["pack_id"],
                         "pack_sha256": pack["seal"]["pack_sha256"],
                         "gate_ready": True,
                         "target_class": pack["target_class"]},
                "receipt_id": receipt["receipt_id"]}

    def _seal_session(self, session, sealed_by):
        if self.inject_seal_failure:
            raise Refusal("EVIDENCE_PACK_FAILURE",
                          "pack seal failed; a session that cannot "
                          "seal does not report closed (§3.2.5)")
        board = self.registry[session["board_id"]]
        # §4.2 class interlock at seal: the pack class is re-derived
        # from the adapter at sealing time; a mismatch seals NOTHING
        # rather than sealing a mislabeled pack.
        declared = self._check_class_integrity(board)
        if declared != session["target_class"]:
            raise Refusal(
                "TARGET_MISMATCH",
                f"adapter declares {declared!r} but the session "
                f"carries {session['target_class']!r}; no pack "
                "seals under a relabeled class (§4.2)")
        adapter = self.adapter_for(session["board_id"])
        sealed_at = now_iso(self.now())
        try:
            console_text = adapter.console_read(1 << 20)["text"]
            power_state = adapter.attest(session["board_id"])[
                "power_state"]
        except Exception:
            console_text, power_state = "", "unknown"
        registers = {f"{tid}|{hex(addr)}": val for (tid, addr), val
                     in getattr(adapter, "regs", {}).items()}
        pack_body = {
            "pack_id": _uid("pack"),
            "session": {k: v for k, v in session.items()
                        if k not in ("chain", "mandate")},
            "mandate": session["mandate"],
            "target_class": session["target_class"],
            "board": board,
            "targets": board.get("targets", []),
            "operations": session["operations"],
            "refusals": session["refusals"],
            "receipts": [],  # filled below, before seal
            "power_acts": session["power_acts"],
            "loads": session["loads"],
            "captures": session["captures"],
            "gap_records": session["gap_records"],
            "strap_state": board.get("strap_state"),
            "opened_at": session["opened_at"],
            "sealed_at": sealed_at,
            "sealed_by": sealed_by,
            "evidence": {"console_text": console_text,
                         "registers": registers,
                         "memory_hashes": session["evidence_memory"],
                         "power_state": power_state},
        }
        pack_body["receipts"] = list(session["chain"].receipts)
        pack = receipts.seal_pack(pack_body, self.bridge_seed)
        self.packs[pack["pack_id"]] = pack
        return pack

    def simulate_drop(self, session_id):
        """§10.4/§11.3: transport death — bridge seals a gap record,
        session DROPPED, board UNKNOWN. Test/admin hook, not a tool."""
        session = self.sessions[session_id]
        gap = {"gap_id": _uid("gap"), "session_id": session_id,
               "detected_at": now_iso(self.now()),
               "last_receipt_seq": len(session["chain"].receipts) - 1,
               "cause": "drop", "board_state_after": "UNKNOWN"}
        session["gap_records"].append(gap)
        session["state"] = "DROPPED"
        self._set_board_state(session, "UNKNOWN")
        pack = self._seal_session(session,
                                  sealed_by="bridge (session dropped)")
        session["pack_id"] = pack["pack_id"]
        lease = self.leases.get(session["board_id"])
        if lease and lease["session_id"] == session_id:
            lease["state"] = "released"
        return pack

    def expire_lease(self, board_id):
        lease = self.leases.get(board_id)
        if lease:
            lease["state"] = "expired"
            session = self.sessions.get(lease["session_id"])
            if session and session["state"] in ("OPEN", "CONNECTED",
                                                "ACTIVE"):
                session["state"] = "EXPIRED"
                if session["board_state"] == "ATTESTED":
                    self._set_board_state(session, "UNKNOWN")

    # ============================================================ admin
    # Owner/admin surface (§6.2) — NOT MCP tools. bridge.py CLI only.
    def admin_tier_arm(self, board_id, session_id, owner_seed: bytes,
                       recovery_path_ref=None):
        """Issue a §5.2 arm record — owner act, admin CLI only, never
        an MCP tool. The record is owner-signed; T3 verbs verify the
        signature at use time (verified-approval pattern). Arm
        expires at session close: expires_at is a far bound, and
        session_close deletes the record (§5.2)."""
        arm = {"arm_id": _uid("arm"), "board_id": board_id,
               "session_id": session_id,
               "armed_by": "owner (admin CLI, §6.2)",
               "armed_at": now_iso(self.now()),
               "expires_at": "2999-01-01T00:00:00+00:00",
               "capture_required": True,
               "recovery_path_ref": recovery_path_ref}
        arm["owner_signature"] = herald_sig.sign(
            owner_seed, receipts.canon(arm).encode()).hex()
        self.arms[arm["arm_id"]] = arm
        return arm

    def admin_bench_freeze_set(self, on: bool):
        self.bench_frozen = bool(on)
        return {"bench_frozen": self.bench_frozen}

    def admin_mandate_revoke(self, mandate_id):
        """Dead-man: freezes NEW ops only; in-flight writes complete;
        power state untouched (§5.1)."""
        self.revoked_mandates.add(mandate_id)
        frozen = []
        for s in self.sessions.values():
            if s["mandate_id"] == mandate_id and s["state"] in (
                    "OPEN", "CONNECTED", "ACTIVE"):
                s["state"] = "FROZEN"
                frozen.append(s["session_id"])
        return {"revoked": mandate_id, "sessions_frozen": frozen}

    def admin_lease_release(self, board_id, reason="owner"):
        lease = self.leases.get(board_id)
        if lease:
            lease["state"] = "released"
        return {"board_id": board_id, "released": bool(lease),
                "reason": reason}

    def admin_pack_export(self, pack_id):
        pack = self.packs.get(pack_id)
        if pack is None:
            raise ToolError(f"PACK_UNKNOWN: {pack_id}")
        return pack


def _summarize(params):
    """Redacted param summary for op records: hashes only for bytes."""
    out = {}
    for k, v in params.items():
        if k in ("bytes_b64",):
            out[k] = f"<{len(v)} chars, hashed in params_hash>"
        elif isinstance(v, dict):
            out[k] = "<record>"
        else:
            out[k] = v
    return out


def _op_params(args):
    return {k: v for k, v in args.items() if k != "session_id"}


# Eclipse Proving MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
