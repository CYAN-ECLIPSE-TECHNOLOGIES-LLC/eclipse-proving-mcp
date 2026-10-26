# Eclipse Proving MCP

**Governed bench access for agents — signed mandates, pinned artifacts, evidence for every session.**

Eclipse Proving is one product family in three Bazaar classes:

| Class | Product | Function |
|---|---|---|
| CONNECTOR | **Eclipse Proving** — the bench bridge | Holds all target connections. Enforces mandate + pins at the wire. Sole path agent→target. |
| MCP SERVER | **Eclipse Proving Session** — board session core | Typed, closed tool surface (22 tools). No raw vendor escape hatch exists on any surface. |
| TOOL | **Eclipse Proving Pin** | Verifies an artifact against its Herald-signed pin record. Offline, third-party runnable. |
| TOOL | **Eclipse Proving Gate** | Runs an assertion set against a sealed evidence pack → `BOOT_VERIFIED \| BOOT_UNVERIFIED`, failing assertion named. |

Spec: `../eclipse-proving-spec-20261025.md` (W-002, 2026-10-25) — the authority for this build.

## The novel mechanism

Physical bench authority is exercised **only** inside a Herald-signed mandate that pins *which agent* may touch *which board* with *which operation classes* and *which exact artifact hashes* — enforced at the bridge that holds the JTAG / serial / power connections — and every session, including its gaps and refusals, is sealed into a Blackbox-form evidence pack a third party can verify offline.

**One-byte rule:** an artifact differing by one byte from its Herald-pinned hash refuses `ARTIFACT_PIN_MISMATCH`, the refusal is receipted into the pack, and the board keeps its prior state. No warning path, no override parameter, no "load anyway" flag exists in the surface.

## Authority tiers

| Tier | Ops | Gates |
|---|---|---|
| T0 read | chain scan, discovery, register/memory/console read, telemetry, strap-state read, attestation | mandate names T0 + board |
| T1 volatile write | bitstream/ELF load, memory write, run/halt | every load pin-gated (§7.1, exact order); board ATTESTED |
| T2 power | power on/off/cycle, reset | **every act receipted**; dead-man rule binds |
| T3 persistent write | boot-media writes | mandate + **owner arm per board per session** (admin CLI only) + **mandatory pre-write image capture** + recorded recovery path |

**Dead-man rule:** revocation/freeze/expiry freeze *new* operations only — the bridge never cuts power inside an active write window; a power op inside a window refuses `POWER_WINDOW_ACTIVE` and is never queued.

**Permanent refusals — no tier, no arm, no override, no tool:** security-fuse programming (`PERMANENT_REFUSED_FUSE`) · PMIC/voltage configuration (`PERMANENT_REFUSED_PMIC`) · boot-mode strap changes (`BOOT_MODE_PHYSICAL`; strap state is read-only, T0).

## P0 scope — read this before believing anything

P0 targets are **fixture** (recorded-trace replay) and **emulator** classes only: AMD QEMU (Xilinx fork) ZCU102 — owner-confirmed primary target, 2026-10-25 — and Renode `zynqmp-zcu102` as the diversity surface. There is **no physical layer at P0**: no real board, probe, PDU, or `hw_server` (the adapter is an interface stub that refuses `ADAPTER_NOT_IN_PHASE`). Emulator/fixture sessions never render or certify as bench sessions; every evidence pack names its target class. The verdict ceiling for this product is **CERTIFIED(simulator)**, and only when Verity's bench (§13) earns it — this build is **bench-pending**.

In this build environment no QEMU/Renode process is present, so the emulator adapters run their XSDB-shaped / monitor-shaped session scripts against a deterministic simulated PS and declare `target_class: emulator` in every record. PL behavior is not modeled by plain QEMU and no PL claim is made; bitstream loads on emulator/fixture targets are recorded with that semantics note.

## Layout

```
server.py          Session MCP server (stdio, 22 tools, §6)
proving_engine.py  Bridge core: mandate/lease/tier/refusal logic, sessions, packs
bridge.py          Pin/Gate standalone dispatch + owner admin CLI (§6.2, NOT MCP)
adapters/          fixture · qemu_xsdb · renode · hwserver (P1 stub only)
pin_tool.py        Eclipse Proving Pin (§7)
gate_tool.py       Eclipse Proving Gate (§8)
receipts.py        Hash-chained receipts + pack seal (§11)
herald_sig.py      Ed25519 (RFC 8032), pure stdlib — Herald verify interface
fixtures/          Synthetic corpus: test keys, registry, signed mandates/pins,
                   artifacts, assertion sets (regenerate: tools/make_fixtures.py)
tests/             §13 bench-plan test suite + self_test_output.txt
smoke.py           Stdio smoke over the wire
BUILD-MANIFEST.json  Build record: spec, target pin, tier map, evidence classes
```

## Run

```bash
python3 tools/make_fixtures.py   # regenerate the deterministic fixture corpus
python3 server.py                # MCP over stdio
python3 smoke.py                 # wire-level smoke
python3 -m unittest discover -s tests   # full suite (31 tests)
```

## Owner admin (never MCP tools)

```bash
python3 bridge.py bench_freeze_set on|off
python3 bridge.py tier_arm --board <board_id> --session <session_id> --recovery-path-ref <ref>
python3 bridge.py mandate_revoke --mandate <mandate_id>
```

The CLI persists acts to `fixtures/control.local.json` / `fixtures/arms.local.json`, loaded by a bridge at start; the same acts exist in-process as `Bridge.admin_*` methods. Arm records are owner-signed and verified at every T3 use; an arm expires at session close and can never be created by an agent.

## Signatures & test keys

Mandates, pins, and arms are Ed25519-signed records verified over canonical JSON at use time — never cached from presentation. P0 uses Herald **test keys** (deterministic, labeled, in `fixtures/keys.json`) behind the same verify interface; production key custody is a gated decision, not a P0 claim. `herald_sig.py` is verified against the RFC 8032 §7.1 test vector in the suite.

---
Eclipse Proving · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
