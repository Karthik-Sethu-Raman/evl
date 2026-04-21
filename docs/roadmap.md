# EVL Roadmap

## 1. Overview

This roadmap outlines the planned evolution of EVL (Encrypted Virtual Locker) from its current state to future advanced capabilities.

The project is structured in incremental phases, prioritizing:

- Correctness first
- Then usability
- Then system-level integration
- Then advanced features

---

## 2. Phase 0.1 — Core Format & Crypto Engine

**Status:** Complete

### Deliverables

- Format specification (`evl_format_v1.md`)
- Design decisions documentation
- Threat model
- Core library in C:
  - Key derivation (Argon2id + HKDF)
  - AES-256-GCM wrapper
  - Random nonce generation
  - AAD construction
  - Header serialization and authentication
  - Block read/write logic

---

## 3. Phase 0.2 — CLI Interface

**Status:** Complete

### Deliverables

- `evl create` — create encrypted container
- `evl write` — encrypt file into container
- `evl read` — decrypt container to stdout
- `evl info` — inspect container metadata
- `evl verify` — verify header authentication

---

## 4. Phase 1.0 — FUSE Integration

**Status:** Complete

### Deliverables

- `evl mount` — mount container as virtual filesystem
- Single virtual file (`locker.bin`) exposed at mountpoint
- Transparent block-level read/write via FUSE callbacks
- Concurrent-safe I/O via `pread`/`pwrite`
- Clean unmount via `evl_fuse_destroy`

### Architecture

```
[FUSE Layer]
     ↓
[EVL Core Library]
     ↓
[.evl File]
```

### Verified

- Full video playback through encrypted FUSE mount
- Byte-perfect round-trip verified via diff
- All security properties verified under active tampering

---

## 5. Phase 2.0 — Multi-File Filesystem Layer (Planned)

**Status:** Planned

### Goals

- Support multiple named files inside a single `.evl` container
- Expose a full directory structure at the mountpoint

### Requires

- On-disk inode/allocation table
- Directory entry structure
- File creation, deletion, rename operations
- FUSE `readdir`, `mkdir`, `unlink`, `rename` callbacks

### Notes

- Cryptographic layer (Phase 1) remains unchanged
- Adds a filesystem abstraction layer on top of existing block I/O

---

## 6. Phase 3.0 — Hardening (Planned)

**Status:** Planned

### Goals

- Block-level replay protection via per-block version counters
- Crash consistency via journaling or atomic write guarantees
- Side-channel resistance (constant-time tag verification)
- Argon2id parameter configurability

### Notes

- Block-level replay requires a persistent, authenticated version table
- Crash consistency requires either journaling or copy-on-write semantics
- Both introduce write ordering constraints and on-disk complexity