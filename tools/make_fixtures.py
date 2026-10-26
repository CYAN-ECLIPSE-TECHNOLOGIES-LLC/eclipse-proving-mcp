#!/usr/bin/env python3
# Eclipse Proving MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# Generate the P0 fixture corpus: test keys, board registry,
# Herald-signed mandates + pins, artifacts, assertion sets (§12.2).

"""Generate fixtures/ deterministically (spec §12.2 synthetic
corpus). TEST KEYS ONLY: seeds derive from labeled strings and are
regenerated identically every run; they exist so mandates, pins,
arms, and pack seals verify through the real Ed25519 interface
(§9: Herald test keys behind the same verify interface). Never
production custody.
"""
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).parent.parent
sys.path.insert(0, str(HERE))
import herald_sig  # noqa: E402
from receipts import canon  # noqa: E402

FX = HERE / "fixtures"
ART = FX / "artifacts"

HERALD_SEED = hashlib.sha256(b"proving-herald-test-seed-v1").digest()
BRIDGE_SEED = hashlib.sha256(b"proving-bridge-test-seed-v1").digest()
OWNER_SEED = hashlib.sha256(b"proving-owner-test-seed-v1").digest()
FORGER_SEED = hashlib.sha256(b"proving-forger-seed-v1").digest()

PART = "xczu9eg-ffvb1156-2-e"
TARGETS = [
    {"target_id": "apu", "kind": "apu", "address_map_ref": "zcu102-ps"},
    {"target_id": "rpu", "kind": "rpu", "address_map_ref": "zcu102-ps"},
    {"target_id": "pmu", "kind": "pmu", "address_map_ref": "zcu102-ps"},
    {"target_id": "pl", "kind": "pl", "address_map_ref": "zcu102-pl"},
]


def sign(seed, record, field="herald_signature"):
    record[field] = herald_sig.sign(
        seed, canon({k: v for k, v in record.items()
                     if k != field}).encode()).hex()
    return record


def pattern(n, seed_byte):
    return bytes((i * 31 + seed_byte) % 256 for i in range(n))


def write(name, obj):
    (FX / name).write_text(json.dumps(obj, indent=1, sort_keys=True))
    print("wrote", name)


def main():
    ART.mkdir(parents=True, exist_ok=True)
    _, herald_pub = herald_sig.keypair_from_seed(HERALD_SEED)
    _, bridge_pub = herald_sig.keypair_from_seed(BRIDGE_SEED)
    _, owner_pub = herald_sig.keypair_from_seed(OWNER_SEED)

    write("keys.json", {
        "herald_pubkey": herald_pub.hex(),
        "bridge_pubkey": bridge_pub.hex(),
        "bridge_seed": BRIDGE_SEED.hex(),
        "owner_pubkey": owner_pub.hex(),
        "known_agents": ["herald-card-w002", "herald-card-w003"],
        "note": "P0 TEST keys (spec §9). bridge_seed is present "
                "because the bridge process is the seal signer; "
                "production custody is a gated decision.",
    })
    (FX / "owner_key.json").write_text(json.dumps(
        {"seed_hex": OWNER_SEED.hex(),
         "note": "TEST owner key for admin-CLI arm signing (§5.2)."}))

    boards = [
        {"board_id": "fixture-zcu102-01", "board_rev": "B",
         "device_part": PART, "silicon_rev": "2.0",
         "dna": "0x1a2b3c4d", "target_class": "fixture",
         "adapter": "fixture", "strap_state": "JTAG",
         "media": [{"media_id": "qspi0", "kind": "qspi",
                    "size_bytes": 4096,
                    "recovery_path_ref": "owner-bench-jtag-restore-v1"}],
         "targets": TARGETS},
        {"board_id": "fixture-norecovery-01", "board_rev": "B",
         "device_part": PART, "silicon_rev": "2.0",
         "dna": "0x5e6f7788", "target_class": "fixture",
         "adapter": "fixture", "strap_state": "JTAG",
         "media": [{"media_id": "qspi0", "kind": "qspi",
                    "size_bytes": 4096}],
         "targets": TARGETS},
        {"board_id": "qemu-zcu102-01", "board_rev": "1.0",
         "device_part": "qemu-zcu102", "silicon_rev": None,
         "dna": None, "target_class": "emulator",
         "adapter": "qemu_xsdb", "strap_state": "JTAG (emulator report)",
         "media": [{"media_id": "sd0", "kind": "sd",
                    "size_bytes": 8192,
                    "recovery_path_ref": "emulator-snapshot-restore-v1"}],
         "targets": TARGETS},
        {"board_id": "renode-zcu102-01", "board_rev": "A",
         "device_part": "renode-zcu102-revA", "silicon_rev": None,
         "dna": None, "target_class": "emulator",
         "adapter": "renode", "strap_state": "JTAG (emulator report)",
         "media": [{"media_id": "sd0", "kind": "sd",
                    "size_bytes": 8192,
                    "recovery_path_ref": "emulator-snapshot-restore-v1"}],
         "targets": TARGETS},
    ]
    write("registry.json", {"boards": boards})

    artifacts = {
        "art-zcu102-elf": ("app.elf", pattern(2048, 7), "elf", {}),
        "art-zcu102-elf-onebyte": ("app-onebyte.elf", None, "elf", {}),
        "art-zcu102-bitstream": ("top.bit", pattern(4096, 21),
                                 "bitstream", {}),
        "art-zcu102-boot": ("boot.bin", pattern(1024, 42),
                            "boot_image", {}),
        "art-slow-elf": ("slow.elf", pattern(2048, 99), "elf",
                         {"window_hold": True}),
        "art-qemu-elf": ("qemu-app.elf", pattern(2048, 55), "elf", {}),
        "art-renode-elf": ("renode-app.elf", pattern(2048, 77),
                           "elf", {}),
    }
    onebyte = bytearray(artifacts["art-zcu102-elf"][1])
    onebyte[100] ^= 0x01  # exactly one byte differs (D-1)
    artifacts["art-zcu102-elf-onebyte"] = (
        "app-onebyte.elf", bytes(onebyte), "elf", {})
    index, hashes = {}, {}
    for ref, (fname, data, klass, extra) in artifacts.items():
        (ART / fname).write_bytes(data)
        index[ref] = {"file": fname, "artifact_class": klass, **extra}
        hashes[ref] = hashlib.sha256(data).hexdigest()
    write("artifacts.json", {"artifacts": index})

    def pin(pid, ref, klass, cons, seed=HERALD_SEED, expires=None):
        p = {"pin_id": pid, "artifact_sha256": hashes[ref],
             "artifact_class": klass,
             "size_bytes": len(artifacts[ref][1]),
             "target_constraints": cons,
             "approver_identity": "herald-approver-owner",
             "approval_scope": "P0 fixture/emulator sessions",
             "issued_at": "2026-10-25T00:00:00+00:00",
             "expires_at": expires}
        return sign(seed, p)

    pins = [
        pin("pin-elf-good", "art-zcu102-elf", "elf",
            {"device_part": PART, "board_id": "fixture-zcu102-01"}),
        pin("pin-bitstream-good", "art-zcu102-bitstream", "bitstream",
            {"device_part": PART, "board_id": "fixture-zcu102-01"}),
        pin("pin-boot-good", "art-zcu102-boot", "boot_image",
            {"device_part": PART, "board_id": "fixture-zcu102-01"}),
        pin("pin-slow-elf", "art-slow-elf", "elf",
            {"device_part": PART, "board_id": "fixture-zcu102-01"}),
        pin("pin-qemu-elf", "art-qemu-elf", "elf",
            {"device_part": "qemu-zcu102",
             "board_id": "qemu-zcu102-01"}),
        pin("pin-renode-elf", "art-renode-elf", "elf",
            {"device_part": "renode-zcu102-revA",
             "board_id": "renode-zcu102-01"}),
        pin("pin-wrong-board", "art-zcu102-elf", "elf",
            {"device_part": PART, "board_id": "qemu-zcu102-01"}),
        pin("pin-expired", "art-zcu102-elf", "elf",
            {"device_part": PART, "board_id": "fixture-zcu102-01"},
            expires="2025-01-01T00:00:00+00:00"),
        pin("pin-revoked", "art-zcu102-elf", "elf",
            {"device_part": PART, "board_id": "fixture-zcu102-01"}),
        pin("pin-forged", "art-zcu102-elf", "elf",
            {"device_part": PART, "board_id": "fixture-zcu102-01"},
            seed=FORGER_SEED),
    ]
    write("pins.json", {"pins": pins})
    write("revocations.json", {"mandates": ["mandate-revoked"],
                               "pins": ["pin-revoked"]})

    def mandate(mid, boards_list, pin_ids, caps, seed=HERALD_SEED,
                agent="herald-card-w002", expires="2027-12-31T00:00:00+00:00",
                max_sessions=50):
        m = {"mandate_id": mid, "agent_identity": agent,
             "principal": "owner-acevvs", "boards": boards_list,
             "pins": pin_ids, "caps": caps,
             "session_bounds": {
                 "max_sessions": max_sessions, "max_duration_s": 3600,
                 "not_before": "2026-01-01T00:00:00+00:00",
                 "expires_at": expires},
             "kill": {"revocation_ref": "herald-revocation-feed (fixture)"},
             "issued_at": "2026-10-25T00:00:00+00:00"}
        return sign(seed, m)

    all_pins = [p["pin_id"] for p in pins]
    generous = {"max_read_bytes": 1_000_000,
                "max_write_bytes": 1_000_000, "max_loads": 100,
                "max_power_cycles": 100}
    mandates = [
        mandate("mandate-full", [
            {"board_id": "fixture-zcu102-01",
             "tiers": ["T0", "T1", "T2", "T3"]},
            {"board_id": "fixture-norecovery-01",
             "tiers": ["T0", "T1", "T2", "T3"]},
            {"board_id": "qemu-zcu102-01", "tiers": ["T0", "T1", "T2"]},
            {"board_id": "renode-zcu102-01",
             "tiers": ["T0", "T1", "T2"]}], all_pins, generous),
        mandate("mandate-t0", [
            {"board_id": "fixture-zcu102-01", "tiers": ["T0"]}],
            [], generous),
        mandate("mandate-capped", [
            {"board_id": "fixture-zcu102-01", "tiers": ["T0", "T1", "T2"]}],
            ["pin-elf-good"],
            {"max_read_bytes": 1024, "max_write_bytes": 64,
             "max_loads": 1, "max_power_cycles": 1}),
        mandate("mandate-expired", [
            {"board_id": "fixture-zcu102-01", "tiers": ["T0"]}],
            [], generous, expires="2025-06-01T00:00:00+00:00"),
        mandate("mandate-revoked", [
            {"board_id": "fixture-zcu102-01", "tiers": ["T0"]}],
            [], generous),
        mandate("mandate-forged", [
            {"board_id": "fixture-zcu102-01", "tiers": ["T0"]}],
            [], generous, seed=FORGER_SEED),
        mandate("mandate-other-agent", [
            {"board_id": "fixture-zcu102-01", "tiers": ["T0"]}],
            [], generous, agent="herald-card-unknown"),
    ]
    write("mandates.json", {"mandates": mandates})

    write("assertion_sets.json", {"sets": [
        {"set_id": "set-boot-basic", "author": "cetech-fixture",
         "created_at": "2026-10-25T00:00:00+00:00",
         "assertions": [
             {"type": "boot_banner", "pattern": "Linux version"},
             {"type": "console_contains", "text": "zynqmp login"},
             {"type": "loaded_hash_eq",
              "artifact_sha256": hashes["art-zcu102-elf"]},
             {"type": "power_state_eq", "expected": "on"},
             {"type": "receipt_chain_valid"}]},
        {"set_id": "set-qemu-boot", "author": "cetech-fixture",
         "created_at": "2026-10-25T00:00:00+00:00",
         "assertions": [
             {"type": "boot_banner", "pattern": "Linux version"},
             {"type": "loaded_hash_eq",
              "artifact_sha256": hashes["art-qemu-elf"]},
             {"type": "power_state_eq", "expected": "on"}]},
        {"set_id": "set-renode-boot", "author": "cetech-fixture",
         "created_at": "2026-10-25T00:00:00+00:00",
         "assertions": [
             {"type": "boot_banner", "pattern": "Linux version"},
             {"type": "loaded_hash_eq",
              "artifact_sha256": hashes["art-renode-elf"]},
             {"type": "power_state_eq", "expected": "on"}]},
        {"set_id": "set-bad-vocab", "author": "cetech-fixture",
         "created_at": "2026-10-25T00:00:00+00:00",
         "assertions": [{"type": "magic_check"}]},
    ]})
    (FX / "traces").mkdir(exist_ok=True)
    (FX / "traces" / "sample_trace.json").write_text(json.dumps({
        "adapter": "fixture",
        "note": "synthetic corpus trace (§12.2); replayed semantics "
                "live in adapters/base.py BOOT_BANNER",
        "console_lines": ["U-Boot 2023.01 ZynqMP ZCU102",
                          "Linux version 6.1.5-xilinx"]}, indent=1))
    print("fixtures complete")


if __name__ == "__main__":
    main()


# Eclipse Proving MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
