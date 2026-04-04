# EVL Design Decisions (v1)

## 1. Overview

This document captures the key architectural and cryptographic decisions made in EVL v1, along with their rationale and tradeoffs.

The goal is to prioritize:

- Correctness
- Simplicity
- Security guarantees
- Implementation feasibility

---

## 2. Why AES-GCM over XTS

**Decision:** Use AES-GCM (AEAD) instead of AES-XTS.

**Rationale:**

AES-GCM provides both confidentiality (encryption) and integrity (authentication tag). AES-XTS provides confidentiality only, with no built-in integrity protection. Without authentication, an attacker can modify ciphertext undetected.

**Tradeoff:**

| Property           | AES-GCM                  | AES-XTS                  |
|--------------------|--------------------------|--------------------------|
| Integrity          | Yes                      | No                       |
| Disk design fit    | General purpose          | Designed for disk sectors |
| Nonce requirement  | Requires nonce discipline | No nonce required        |

**Conclusion:** AES-GCM is chosen because EVL requires tamper detection, not just encryption.

---

## 3. Why Block-Level AES-GCM

**Decision:** Encrypt data in independent blocks.

**Rationale:**

- Enables random access
- Avoids re-encrypting the entire file on partial writes
- Limits corruption impact to one block

**Tradeoff:** Requires explicit structure binding via AAD and manual ordering enforcement.

**Conclusion:** Block-level design aligns with filesystem-like behavior and scalability.

---

## 4. Why Deterministic Nonce

**Decision:** Derive nonce from:

```
file_id || block_index || version
```

**Rationale:**

- Eliminates the need to store nonces on disk
- Guarantees reproducibility during decryption
- Prevents accidental nonce reuse

**Critical requirement:** Nonce **MUST** be unique per (key, encryption instance). Version **MUST** be included to prevent reuse on overwrite.

**Conclusion:** Deterministic nonce derivation is safe given the controlled input space.

---

## 5. Why Argon2id

**Decision:** Use Argon2id for password-based key derivation.

**Rationale:** Argon2id is memory-hard, resistant to GPU-based attacks, and is the recommended modern standard for password hashing.

**Alternatives considered:**

- PBKDF2 — weaker against GPU attacks
- bcrypt — less flexible

**Conclusion:** Argon2id provides strong resistance against offline attacks.

---

## 6. Why HKDF (Key Separation)

**Decision:** Derive multiple keys from the master key via HKDF.

**Rationale:** Using the same key for both header authentication and block encryption creates cross-protocol leakage risk. HKDF derives independent keys for each role.

**Conclusion:** Key separation improves robustness and reduces attack surface.

---

## 7. Why Global Versioning

**Decision:** Use a single version counter per file.

**Rationale:**

- Prevents replay of old blocks
- Simpler than per-block versioning
- Avoids metadata complexity

**Tradeoff:** Does not prevent full file rollback; versioning is coarse-grained.

**Alternatives rejected:** Per-block versioning introduces complex metadata, consistency issues, and higher implementation risk.

**Conclusion:** Global versioning provides sufficient protection for v1.

---

## 8. Why No Padding

**Decision:** Do not pad blocks.

**Rationale:** AES-GCM (CTR mode) supports variable-length input natively. Padding introduces unnecessary complexity and potential vulnerabilities.

**Conclusion:** The last block is stored as-is; `file_size` is used to determine valid byte length.

---

## 9. Why Little-Endian Encoding

**Decision:** Use little-endian for all integers.

**Rationale:** Matches x86 architecture conventions and simplifies implementation. Endianness **MUST** be fixed and consistent — a mismatch in encoding produces AAD mismatches, nonce mismatches, and authentication failures.

**Conclusion:** Little-endian encoding is required for interoperability.

---

## 10. Why Plaintext Header with Authentication

**Decision:** Header is not encrypted, only authenticated.

**Rationale:** Keeping the header in plaintext simplifies parsing and debugging. Integrity is still guaranteed via the authentication tag.

**Tradeoff:** Header metadata is visible (not confidential).

**Conclusion:** Chosen for simplicity in v1.

---

## 11. Why Include `block_index` in AAD

**Decision:** Include `block_index` in AAD.

**Rationale:** Binds each ciphertext block to its position in the file. Without it, an attacker can reorder blocks undetected.

**Conclusion:** `block_index` is critical for structural integrity.

---

## 12. Why Include `block_size` in AAD

**Decision:** Include `block_size` in AAD.

**Rationale:** Prevents header tampering from silently affecting block parsing. Ensures structural consistency between what the header declares and what was encrypted.

**Conclusion:** Protects metadata-dependent interpretation.

---

## 13. Why Include `version` in AAD

**Decision:** Include `version` in AAD.

**Rationale:** Prevents replay of old blocks by binding each encryption to the file's current version counter.

**Conclusion:** `version` is required for intra-file replay protection.

---

## 14. Why SHA-256 for Nonce Derivation

**Decision:** Use SHA-256 to derive per-block nonces.

**Rationale:** SHA-256 is deterministic, produces uniform output, and has negligible collision probability over the expected input space.

**Tradeoff:** Slight computational overhead per block access.

**Conclusion:** Acceptable for v1; can be optimized in later versions.

---

## 15. Why No Full Rollback Protection

**Decision:** Do not protect against full file rollback.

**Rationale:** Full rollback protection requires external trusted state — a TPM, remote counter, or trusted server. This is out of scope for v1.

**Conclusion:** Explicit design limitation; documented in the format spec.

---

## 16. Why FUSE Instead of a Kernel Module

**Decision:** Use a user-space filesystem via FUSE.

**Rationale:**

- Faster development cycle
- Easier debugging (no kernel crashes)
- Portable across Linux systems

**Alternatives rejected:** A kernel module (`.ko`) is complex, unsafe to iterate on, and harder to debug without significant added benefit at this stage.

**Conclusion:** FUSE is appropriate for the initial implementation.

---

## 17. Why Not a Virtual Block Device

**Decision:** Avoid a virtual block device (VBD) for v1.

**Rationale:** VBD requires kernel-level integration and carries significantly higher complexity without being necessary for core functionality.

**Conclusion:** VBD is deferred as future work.

---

## 18. Summary

EVL v1 prioritizes:

- Correctness over optimization
- Simplicity over feature completeness
- Strong integrity guarantees
- Minimal attack surface