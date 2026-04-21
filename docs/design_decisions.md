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

## 4. Why Random Nonce

**Decision:** Generate a fresh 12-byte nonce per block encryption using a CSPRNG (`RAND_bytes`), stored on disk alongside each block.

**Rationale:**

Deterministic nonce derivation was considered first, using `SHA-256(file_id || block_index || version)`. This approach was rejected because guaranteeing nonce uniqueness across rewrites requires a version counter that changes with every write. A global version counter fails this — it changes on every write but is not tracked per block, meaning a re-encrypted block and an unchanged block can end up with mismatched version assumptions. Closing this correctly requires per-block version tracking, which introduces version table authentication, write ordering constraints, and crash consistency exposure — complexity out of scope for v1.

Random nonces achieve the same security goal (nonce uniqueness per encryption) without any of this complexity. Uniqueness is guaranteed by the CSPRNG rather than by protocol invariants that must be manually maintained.

**Tradeoff:** Nonces must be stored on disk, adding 12 bytes per block. Reproducibility during decryption is maintained because the nonce is read from the stored block rather than derived.

**Critical requirement:** Nonce **MUST** be generated fresh on every encryption of a block, including rewrites. Reusing a stored nonce on overwrite is forbidden.

**Conclusion:** Random nonces are simpler, correct by construction, and eliminate a class of protocol errors that deterministic nonces require careful discipline to avoid.

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

## 7. Why No Block-Level Replay Protection

**Decision:** Do not protect against block-level replay by a snapshot attacker.

**Rationale:**

Under random nonces, version in AAD does not prevent block-level replay. An attacker who captures a snapshot of the file at time T holds the complete `[nonce | ciphertext | tag]` unit for each block. Substituting an old block back into a newer file passes all authentication checks regardless of whether a version field is present in AAD, because the replayed block carries its own self-consistent nonce and tag generated under the same key.

Closing this attack requires per-block version tracking: a persistent, authenticated counter per block that increments on every rewrite and is verified at decrypt time. This introduces a version table as a new on-disk structure, version table authentication, write ordering constraints between the block and its counter, and crash consistency exposure. This is out of scope for v1.

**Alternatives rejected:** Global version counter in AAD — provides false confidence under random nonces without per-block tracking. Per-block versioning — correct but introduces filesystem-level consistency complexity.

**Conclusion:** Block-level replay is a documented limitation. A snapshot attacker can substitute an old block undetected. This is explicitly out of scope for v1 and requires per-block versioning to close in a future phase.

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

## 13. Why `version` Was Removed from AAD

**Decision:** Do not include `version` in AAD.

**Rationale:** Under random nonces, version in AAD provides no security guarantee against block-level replay. A snapshot attacker replays the entire `[nonce | ciphertext | tag]` unit, which was generated self-consistently at encryption time. The version field in AAD would need to match the version *at the time of encryption of that specific block*, not the current file version — meaning the reader must know the per-block version to reconstruct the correct AAD, which requires per-block version storage. Without that, the field either always matches (useless) or always mismatches (breaks decryption). See decision #7 for the full analysis.

**Conclusion:** `version` is removed from AAD. Block-level replay is a documented out-of-scope limitation.

---

## 14. Why CSPRNG for Nonce Generation

**Decision:** Use `RAND_bytes` (OpenSSL CSPRNG) to generate per-block nonces.

**Rationale:** Nonce uniqueness is the only hard requirement for AES-GCM security. A CSPRNG producing 96-bit random values has a collision probability of approximately 1 in 2^96 per pair, which is negligible across any realistic number of blocks. This is simpler and more robust than deterministic derivation, which requires careful protocol invariants to guarantee uniqueness across rewrites.

**Conclusion:** CSPRNG nonce generation is the standard approach for random-access encrypted storage and is correct by construction.

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

**Conclusion:** FUSE is appropriate for the initial implementation. Implemented in Phase 1.

---

## 17. Why Not a Virtual Block Device

**Decision:** Avoid a virtual block device (VBD) for v1.

**Rationale:** VBD requires kernel-level integration and carries significantly higher complexity without being necessary for core functionality.

**Conclusion:** VBD is deferred as future work. FUSE (Phase 1) is the current mount mechanism.

---

## 18. Summary

EVL v1 prioritizes:

- Correctness over optimization
- Simplicity over feature completeness
- Strong integrity guarantees
- Minimal attack surface

**Known limitations accepted in v1:**

- No block-level replay protection (requires per-block versioning, deferred)
- No full file rollback protection (requires external trusted state, out of scope)
- No crash consistency guarantees (no journaling or atomic writes)