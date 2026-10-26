# Eclipse Proving — P0 Build Manifest

- **Product:** Eclipse Proving (connector) · Eclipse Proving Session (MCP server) · Eclipse Proving Pin (tool) · Eclipse Proving Gate (tool)
- **Spec:** `~/workspace/cyan-eclipse/eclipse-proving-spec-20261025.md` (495 lines, W-002, 2026-10-25) — the authority; build steps X0–X6 (§12.4)
- **Built:** 2026-10-25, W-002 (Silas Forge role)
- **Status:** BENCH-PENDING. Verdict ceiling **CERTIFIED(simulator)** — no certification is claimed by this build.
- **Git / Bazaar:** no commit, no push, no publish (Rook handles placement after Verity's verdict).

## Freeze / target pin (§12.1 — satisfied)

**Freeze status: LIFTED. Owner confirmed 2026-10-25 21:43 ET: P0 target pin = AMD QEMU (Xilinx fork), ZCU102.** Spec §12.1 satisfied.

| Target | Class | Role |
|---|---|---|
| AMD QEMU (Xilinx fork), ZCU102 (`xilinx-zcu102` BSP), XSDB via GDB/TCF | emulator | **Primary** (owner-confirmed) |
| Renode `zynqmp-zcu102-revA/revB` | emulator | Diversity (proves core is not XSDB-shaped) |
| Recorded-trace fixtures (synthetic corpus) | fixture | Deterministic logic benching |
| HwServerAdapter | bench | **P1 only** — interface stub, refuses `ADAPTER_NOT_IN_PHASE`; no implementation, no physical claim |

Environment honesty: no QEMU/Renode process exists in this build environment, so the emulator adapters run their session scripts against a deterministic simulated PS and declare `target_class: emulator` in every record. Nothing is upgraded: an emulator session never renders as a bench session (§3.2.8).

## Tools (22 — exact, bench-asserted)

Session (16): `bench_discover` `session_open` `session_status` `target_connect` `target_attest` `register_read` `memory_read` `console_read` `artifact_load` `memory_write` `target_run` `target_halt` `power_set` `target_reset` `persistent_write` `session_close`
Pin (3): `pin_verify` `pin_show` `pin_status` · Gate (3): `gate_run` `pack_verify` `gate_assertions_check`
Supporting op (not a surface tool, §6.1): `persistent_capture` — bridge-level, inside tool 15's flow.

## Tier map

T0 read · T1 volatile write (pin-gated) · T2 power (every act receipted) · T3 persistent write (owner-armed + pre-write capture + recovery path). Full per-tool map in `BUILD-MANIFEST.json`.

## Refusals

All 35 §9.4 codes implemented verbatim (string-diff test against the spec text in the suite). Permanent refusals have no tool and no adapter call site: `PERMANENT_REFUSED_FUSE`, `PERMANENT_REFUSED_PMIC`, `BOOT_MODE_PHYSICAL` (strap = T0 read only). Denied §6.4 parameter names refuse at the boundary, receipted, mapped to their permanent codes where one exists.

## Evidence classes (per pack type)

fixture board → pack class `fixture` · QEMU board → `emulator` · Renode board → `emulator`. Gate verdicts inherit the pack's class. Self-test evidence is fixture/emulator only.

## Self-test

`tests/self_test_output.txt` — 31 tests, OK: §13.1 functional, D-1/D-2/D-3, H-1…H-15, adapter parity, T3 arm/capture/recovery, caps boundaries, refusal-enum diff, RFC 8032 vector, 510-case schema-enumerating fuzz with valid context. `smoke.py` → SMOKE OK over real stdio.

## Ambiguities resolved (detail in BUILD-MANIFEST.json)

1. QEMU/Renode liveness in this environment (simulated PS, emulator class; NO live-transport binding exists in this build — no code binds one and no switch enables one).
2. `persistent_capture` reachability vs the exact-22 surface (bridge-level op, absent from tools/list).
3. Pack `evidence` snapshot section added for Gate assertions (all §11.1 mandatory sections present).
4. Caps read as cumulative per-mandate ceilings; boundary-exact refusal tested.
5. Seal = pack-level signed record binding chain head + pack hash; close op receipted into its own pack first.
6. Pre-session/boundary refusals receipt into the bridge refusal log chain (§9.1 refusal record).
7. Op on an expired-lease session refuses `LEASE_EXPIRED` (H-5), not `SESSION_FROZEN`.

---
Eclipse Proving · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
