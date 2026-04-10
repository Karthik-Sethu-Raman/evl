# EVL Threat Model (v1)

## 1. Overview

This document defines the threat model for EVL v1, including:

- Attacker capabilities
- Security goals
- Protections provided
- Limitations and non-goals

The model assumes a **hostile storage environment** where attackers can fully access and manipulate the `.evl` file.

---

## 2. Assets

### 2.1 Confidential Data

File contents (plaintext blocks).

### 2.2 Integrity of Data

- Correctness of stored data
- Detection of unauthorized modifications

### 2.3 Structural Integrity

- Block ordering
- File structure (header + layout)

---

## 3. Attacker Model

### 3.1 Full File Access

The attacker can read, copy, modify, delete, or truncate the entire `.evl` file.

### 3.2 Active Manipulation Capabilities

The attacker can modify ciphertext, modify authentication tags, swap or reorder blocks, substitute blocks captured from older file snapshots, and modify header fields.

### 3.3 Offline Attack Capability

The attacker can perform brute-force password attacks, analyze file contents offline, and attempt cryptographic attacks.

### 3.4 Attacker Limitations

The attacker does **not** have:

- Access to the user's password
- Access to derived encryption keys
- Ability to break AES-GCM or Argon2id

---

## 4. Security Goals

### 4.1 Confidentiality

Plaintext data cannot be recovered without the password.

### 4.2 Integrity

Any modification to data is detected.

### 4.3 Structural Integrity

Data cannot be rearranged or misinterpreted without detection.

### 4.4 Nonce Freshness

Each block encryption uses a unique nonce, preventing ciphertext reuse under the same key.

---

## 5. Security Mechanisms

### 5.1 Encryption (Confidentiality)

AES-GCM (CTR mode) protects plaintext data from disclosure.

### 5.2 Authentication (Integrity)

The GCM authentication tag detects any modification to ciphertext or AAD.

### 5.3 AAD Binding (Structural Protection)

AAD is constructed as:

```
file_id || block_index || block_size
```

This prevents block swapping, cross-file substitution, and structural tampering. Version is not included — see Section 7.5 for why block-level replay is an explicit limitation.

### 5.4 Random Nonce Generation (Nonce Freshness)

A fresh 12-byte nonce is generated via CSPRNG (`RAND_bytes`) on every block encryption, including rewrites. The nonce is stored on disk with the block. This guarantees nonce uniqueness across all encryptions under the same key without requiring any version tracking.

### 5.5 Header Authentication

The header is authenticated via AES-GCM, preventing metadata tampering.

### 5.6 Key Derivation Security

Argon2id protects against brute-force attacks. The salt prevents precomputation attacks.

---

## 6. Attack Scenarios and Mitigations

| # | Attack | Mitigation |
|---|--------|------------|
| 6.1 | Modify ciphertext bytes | GHASH mismatch → tag verification fails |
| 6.2 | Modify authentication tag | Tag mismatch → decryption fails |
| 6.3 | Swap `BLOCK_i` and `BLOCK_j` | `block_index` in AAD → mismatch → failure |
| 6.4 | Insert block from another file | `file_id` in AAD → mismatch → failure |
| 6.5 | Substitute block from captured snapshot | **Not mitigated** — entire `[nonce\|ciphertext\|tag]` unit is self-consistent; see Section 7.5 |
| 6.6 | Modify header fields | Header authentication fails → reject file |
| 6.7 | Force nonce reuse | Fresh `RAND_bytes(12)` per encryption → collision probability negligible (≈1/2⁹⁶ per pair) |
| 6.8 | Offline password brute-force | Argon2id → high computational and memory cost |

---

## 7. Non-Goals and Limitations

### 7.1 Full File Rollback

Replacing the entire file with an older version is **not prevented**. This would require external trusted state (TPM, remote counter), which is out of scope for v1.

### 7.2 Crash Consistency

Partial writes may corrupt the file. No journaling or atomic write guarantees are provided.

### 7.3 Side-Channel Attacks

Timing attacks and memory leakage are not addressed in v1.

### 7.4 Weak Passwords

The security of the system depends on the strength of the user's password. EVL provides no enforcement or policy on password quality.

### 7.5 Block-Level Replay

Substitution of a block captured from an older snapshot of the file is **not prevented**. Under random nonces, a stored `[nonce | ciphertext | tag]` unit is self-consistent — it was generated legitimately under the same key, so all authentication checks pass regardless of when it was created. Preventing this requires a per-block version counter that is persistently tracked, authenticated, and verified at decrypt time. This introduces version table authentication, write ordering constraints, and crash consistency exposure that are out of scope for v1. This limitation is distinct from full file rollback (Section 7.1) — it applies at the granularity of individual blocks.

---

## 8. Trust Assumptions

### 8.1 Cryptographic Primitives

The following are assumed secure:

- AES-GCM
- Argon2id
- HKDF (HMAC-SHA256)

### 8.2 Implementation Correctness

- No bugs in cryptographic usage
- Fresh nonce generated on every block encryption, including rewrites
- Proper tag verification before returning plaintext

---

## 9. Failure Policy

On authentication failure:

- Do **NOT** return plaintext
- Abort the operation immediately

On header failure:

- Reject the entire file

---

## 10. Summary

EVL v1 provides strong confidentiality, strong integrity, and protection against structural attacks (block swapping, cross-file substitution, header tampering). Nonce freshness is guaranteed by CSPRNG generation on every encryption.

EVL v1 does **not** provide block-level replay protection, full file rollback protection, crash safety, side-channel resistance, or protection against weak passwords.