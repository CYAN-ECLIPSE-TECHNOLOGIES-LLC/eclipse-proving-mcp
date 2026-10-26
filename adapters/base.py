#!/usr/bin/env python3
# Eclipse Proving MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# TargetAdapter interface (§4.2) + shared simulated-target state.

"""TargetAdapter interface (spec §4.2) + simulated target state.

All target contact flows through this interface; the core contains
zero vendor calls. P0 implementations are fixture/emulator-class:
they simulate PS memory, registers, console, power, and persistent
media honestly under their declared target_class (sealed into
every pack, §4.3) and never claim bench behavior (§3.2.8).
"""
import hashlib
import threading


class AdapterError(Exception):
    """Adapter-level failure, named — never a bare internal error."""


# Address map for the reference target class (ZCU102-shaped):
# (name, lo, hi_inclusive). Reads/writes outside refuse in engine.
ADDRESS_MAP = [
    ("OCM", 0xFFFC0000, 0xFFFFFFFF),
    ("PS_REGISTERS", 0xFF000000, 0xFF0FFFFF),
    ("DDR_LOW", 0x00000000, 0x7FFFFFFF),
]

BOOT_BANNER = [
    "Xilinx ZynqMP First Stage Boot Loader",
    "Release 2023.1  Oct 25 2026 - 00:00:00",
    "U-Boot 2023.01 (Oct 25 2026 - 00:00:00 +0000) ZynqMP ZCU102",
    "Model: ZynqMP ZCU102 Rev1.0",
    "Starting kernel ...",
    "Linux version 6.1.5-xilinx (gcc 12.2.0) ZynqMP",
    "zynqmp login: root (automatic login)",
]


def in_map(address: int) -> bool:
    return any(lo <= address <= hi for _, lo, hi in ADDRESS_MAP)


class SimulatedTarget:
    """Deterministic simulated PS shared by P0 adapters.

    Adapter-parity (spec X5): fixture/QEMU/Renode runs of the same
    session script yield identical governance outcomes; only the
    adapter name, semantics notes, and console flavor differ.
    """

    adapter_name = "simulated"
    target_class = "fixture"
    pl_modeled = False

    def __init__(self, board: dict):
        self.board = board
        self.connected = False
        self.power = "off"
        self.mem = {}
        self.regs = {}
        self.console = []
        self.core_state = {}
        self.programmed = {}   # target_id -> artifact sha256 loaded
        self.media = {}        # media_id -> bytearray
        # Window-hold event starts UNSET: only window_hold loads
        # ever wait on it, and a release that lands before the load
        # thread arrives must not be lost (no clear-on-entry race).
        self._window_release = threading.Event()
        self.load_calls = []   # spy surface for bench (H-7/D-1)
        for t in board.get("targets", []):
            self.core_state[t["target_id"]] = "halted"
        for m in board.get("media", []):
            size = int(m["size_bytes"])
            self.media[m["media_id"]] = bytearray(
                (i * 7 + 13) % 256 for i in range(size))

    # -- lifecycle -------------------------------------------------
    def enumerate(self):
        return [self.board]

    def connect(self, board_id):
        if board_id != self.board["board_id"]:
            raise AdapterError(f"BOARD_UNKNOWN: {board_id}")
        self.connected = True
        return {"connected": True, "adapter": self.adapter_name,
                "target_class": self.target_class}

    def disconnect(self):
        self.connected = False
        return {"connected": False}

    def attest(self, board_id):
        return {
            "board_id": self.board["board_id"],
            "device_part": self.board["device_part"],
            "board_rev": self.board["board_rev"],
            "dna": self.board.get("dna"),
            "power_state": self.power,
            "programmed": dict(self.programmed),
            "console_tail_sha256": hashlib.sha256(
                "\n".join(self.console).encode()).hexdigest(),
            "target_class": self.target_class,
        }

    def chain_scan(self):
        return {"targets": [
            {"target_id": t["target_id"], "kind": t["kind"],
             "device_part": self.board["device_part"],
             "dna": self.board.get("dna")}
            for t in self.board.get("targets", [])],
            "chain_state": "ok" if self.connected else "disconnected"}

    def strap_state(self):
        return self.board.get("strap_state", "JTAG")

    # -- memory / registers ----------------------------------------
    def register_read(self, target_id, address, width):
        return {"value": self.regs.get((target_id, address), 0)}

    def memory_read(self, target_id, address, length):
        data = bytes(self.mem.get(address + i, 0) for i in range(length))
        return {"bytes": data, "sha256": hashlib.sha256(data).hexdigest()}

    def memory_write(self, target_id, address, data: bytes):
        for i, byte in enumerate(data):
            self.mem[address + i] = byte
        digest = hashlib.sha256(data).hexdigest()
        return {"written_sha256": digest}

    # -- loads -------------------------------------------------------
    def _maybe_hold(self, artifact_meta):
        """Fixture long-load: hold the write window until released
        (dead-man tests H-9/H-10 drive this deterministically)."""
        if artifact_meta and artifact_meta.get("window_hold"):
            self._window_release.wait(timeout=30)

    def release_window(self):
        self._window_release.set()

    def load_bitstream(self, target_id, data: bytes, artifact_meta=None):
        self.load_calls.append(("bitstream", target_id,
                                hashlib.sha256(data).hexdigest()))
        digest = hashlib.sha256(data).hexdigest()
        self._maybe_hold(artifact_meta)
        self.programmed[target_id] = digest
        note = None if self.pl_modeled else (
            "PL not modeled by this target class at P0 — load "
            "recorded, no PL-behavior claim (spec §12.2)")
        return {"loaded_sha256": digest, "readback_sha256": digest,
                "semantics_note": note}

    def load_elf(self, target_id, data: bytes, artifact_meta=None):
        self.load_calls.append(("elf", target_id,
                                hashlib.sha256(data).hexdigest()))
        digest = hashlib.sha256(data).hexdigest()
        self._maybe_hold(artifact_meta)
        self.programmed[target_id] = digest
        self.core_state[target_id] = "halted"
        return {"loaded_sha256": digest, "readback_sha256": digest,
                "semantics_note": None}

    # -- run control / console --------------------------------------
    def run(self, target_id):
        self.core_state[target_id] = "running"
        if not self.console:
            self.console.extend(BOOT_BANNER)
        return {"core_state": "running"}

    def halt(self, target_id):
        self.core_state[target_id] = "halted"
        return {"core_state": "halted", "pc": "0x0000000000100000"}

    def console_read(self, max_bytes):
        text = "\n".join(self.console)
        raw = text.encode()
        truncated = len(raw) > max_bytes
        return {"text": raw[:max_bytes].decode(errors="replace"),
                "truncated": truncated}

    # -- power ---------------------------------------------------------
    def power_set(self, state):
        prior = self.power
        if state == "cycle":
            self.power = "on"
        else:
            self.power = state
        if self.power == "off":
            self.programmed = {}
            for tid in self.core_state:
                self.core_state[tid] = "halted"
        return {"prior_state": prior, "new_state": self.power}

    def reset(self, target_id, kind):
        if target_id:
            self.core_state[target_id] = "halted"
        return {"reset": kind, "target_id": target_id}

    # -- persistent media ---------------------------------------------
    def persistent_read(self, media_id):
        if media_id not in self.media:
            raise AdapterError(f"MEDIA_UNKNOWN: {media_id}")
        return bytes(self.media[media_id])

    def persistent_write(self, media_id, data: bytes):
        if media_id not in self.media:
            raise AdapterError(f"MEDIA_UNKNOWN: {media_id}")
        buf = self.media[media_id]
        buf[:len(data)] = data
        return {"written_sha256": hashlib.sha256(
            bytes(buf)).hexdigest(),
            "media_sha256_after": hashlib.sha256(bytes(buf)).hexdigest()}


# Eclipse Proving MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
