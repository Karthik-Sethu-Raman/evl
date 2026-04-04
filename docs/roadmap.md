# EVL Roadmap

## 1. Overview

This roadmap outlines the planned evolution of EVL (Encrypted Virtual Locker) from its current state to future advanced capabilities.

The project is structured in incremental phases, prioritizing:

- Correctness first
- Then usability
- Then system-level integration
- Then advanced features

> This document covers Phases 0.1 through 1.0. Later phases are planned but not yet documented.

---

## 2. Phase 0.1 — Core Format & Crypto Engine (Pre-FUSE)

**Status:** In Progress

### Goals

- Define EVL file format (v1)
- Implement core cryptographic pipeline
- Ensure correctness and integrity guarantees

### Deliverables

- Format specification (`evl_format_v1.md`)
- Design decisions documentation
- Threat model
- Core library implementation in C:
  - Key derivation (Argon2id + HKDF)
  - AES-GCM wrapper
  - Nonce derivation
  - AAD construction
  - Header parsing and authentication
  - Block read/write logic

### Out of Scope

- FUSE integration
- CLI usability
- Performance optimization
- Crash consistency

---

## 3. Phase 0.2 — CLI Interface

### Goals

Provide basic user interaction with EVL files.

### Features

- Create EVL file
- Open EVL file
- Read/write data
- Inspect metadata

### Notes

- Still operates on EVL as a raw file (not a mounted filesystem)
- Acts as a testing layer for the core engine

---

## 4. Phase 1.0 — FUSE Integration

### Goals

Mount EVL as a virtual filesystem using FUSE.

### Features

- File mounting and unmounting
- Read/write via standard file operations
- Transparent encryption and decryption

### Architecture

```
[FUSE Layer]
     ↓
[EVL Core Library]
     ↓
[.evl File]
```

### Rationale

- User-space implementation avoids kernel-level complexity
- Easier to debug and iterate on than a kernel module