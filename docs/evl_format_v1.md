# EVL Format Specification v1

## 1. Overview

EVL (Encrypted Virtual Locker) is a block-based encrypted file container that provides:

- Confidentiality using AES-GCM
- Integrity via authenticated encryption
- Structural protection using AAD (Additional Authenticated Data)

The file is structured as:

```
[ HEADER | HEADER_TAG | BLOCK_0 | BLOCK_1 | ... ]
```

---

## 2. Constants

### 2.1 Format Identification

| Constant       | Value  | Type      |
|----------------|--------|-----------|
| MAGIC          | `EVL1` | 4 bytes, ASCII |
| FORMAT_VERSION | `1`    | uint8     |

### 2.2 Cryptographic Parameters

| Constant    | Value   |
|-------------|---------|
| AEAD Scheme | AES-GCM |
| TAG_SIZE    | 16 bytes |
| NONCE_SIZE  | 12 bytes |
| SALT_SIZE   | 32 bytes |
| FILE_ID_SIZE| 16 bytes |

### 2.3 Key Derivation

| Role       | Algorithm  |
|------------|------------|
| KDF        | Argon2id   |
| Key Expansion | HKDF    |

Derived keys:

- `enc_key` — block encryption
- `header_key` — header authentication

### 2.4 Encoding Rules

- All integers **MUST** use little-endian encoding
- No padding is allowed
- All sizes are in bytes

### 2.5 Default Parameters

| Constant           | Value      |
|--------------------|------------|
| DEFAULT_BLOCK_SIZE | 4096 bytes |

### 2.6 Nonce Generation

Per-block nonces are generated using a CSPRNG (`RAND_bytes`) at encryption time and stored on disk with each block.

---

## 3. Header Layout

### 3.1 Structure

The header is stored in plaintext and authenticated separately.

```
[ HEADER | HEADER_TAG ]
```

### 3.2 Field Layout

| Offset | Size | Field          | Type       | Description        |
|--------|------|----------------|------------|--------------------|
| 0      | 4    | magic          | ASCII      | `EVL1`             |
| 4      | 1    | format_version | uint8      | Must be `1`        |
| 5      | 32   | salt           | byte[32]   | Argon2id salt      |
| 37     | 16   | file_id        | byte[16]   | Unique identifier  |
| 53     | 8    | file_size      | uint64 LE  | Logical size       |
| 61     | 4    | block_size     | uint32 LE  | Block size         |

### 3.3 Header Size

```
HEADER_SIZE     = 65 bytes
HEADER_TAG_SIZE = 16 bytes
```

### 3.4 Header Authentication

```
header_tag = AES-GCM(header_key, nonce_header, HEADER, AAD_header)
```

### 3.5 Header Nonce

```
nonce_header = first 12 bytes of SHA-256(file_id || "HEADER")
```

### 3.6 Header AAD

```
AAD_header = "EVL_HEADER_V1"
```

### 3.7 Validation Rules

On file open:

1. Read `HEADER` and `HEADER_TAG`
2. Derive `header_key`
3. Recompute `nonce_header`
4. Verify authentication tag

On failure:

> Reject file (invalid or tampered)

---

## 4. Block Structure

### 4.1 Layout

```
BLOCK_i = [ nonce_i | ciphertext_i | tag_i ]
```

- `nonce_i` — 12 bytes, randomly generated at encryption time
- `ciphertext_i` — ≤ block_size bytes
- `tag_i` — 16 bytes

### 4.2 Final Block

- May be smaller than `block_size`
- No padding is used
- Length determined using `file_size`

---

## 5. AAD (Additional Authenticated Data)

### 5.1 Layout

```
[file_id     : 16 bytes]
[block_index : uint64 LE]
[block_size  : uint32 LE]
```

```
AAD_SIZE = 28 bytes
```

### 5.2 Purpose

- Prevent block swapping
- Prevent cross-file substitution
- Bind structural parameters

> **Note:** Block-level replay protection (substitution of an old block from a file snapshot) is explicitly out of scope for v1. See Section 12.

---

## 6. Nonce Generation

```
nonce_i = RAND_bytes(12)   // generated fresh at encryption time
```

Stored on disk as the first 12 bytes of each block (see Section 4.1).

### 6.1 Requirements

- **MUST** be generated fresh on every encryption of a block, including rewrites
- **MUST NOT** be reused across encryptions under the same key
- Reusing a stored nonce on overwrite is forbidden

---

## 7. Block Encryption

```
nonce_i                    = RAND_bytes(12)
(ciphertext_i, tag_i)      = AES-GCM(enc_key, nonce_i, plaintext_block_i, AAD_i)
stored_block_i             = [ nonce_i | ciphertext_i | tag_i ]
```

---

## 8. Block Offset Calculation

```
BLOCK_OFFSET(i) = HEADER_SIZE
                + HEADER_TAG_SIZE
                + i * (NONCE_SIZE + block_size + TAG_SIZE)
```

---

## 9. File Operations

### 9.1 Creation

1. Generate `salt`
2. Derive `master_key` via Argon2id
3. Derive `enc_key`, `header_key` via HKDF
4. Generate `file_id`
5. Build header
6. Compute `header_tag`

### 9.2 Read

For offset `off`:

```
i = off / block_size
```

For each block:

1. Read block
2. Extract `nonce_i` from first 12 bytes of stored block
3. Reconstruct AAD
4. Decrypt and verify

For the final block:

```
valid_bytes = file_size - i * block_size
```

### 9.3 Write

1. Identify affected blocks
2. For each affected block: generate fresh `nonce_i` via `RAND_bytes`
3. Re-encrypt modified blocks
4. Store `[ nonce_i | ciphertext_i | tag_i ]`

### 9.4 Partial Writes

- The entire block **MUST** be rewritten
- Read-modify-write is required

---

## 10. Failure Handling

| Failure         | Action            |
|-----------------|-------------------|
| Header failure  | Reject entire file |
| Block failure   | Reject block read  |

---

## 11. Security Properties

| Property             | Mechanism                          |
|----------------------|------------------------------------|
| Confidentiality      | AES-CTR (GCM)                      |
| Integrity            | GCM authentication tag             |
| Position binding     | `block_index` in AAD               |
| Cross-file binding   | `file_id` in AAD                   |
| Nonce freshness      | CSPRNG per encryption              |

---

## 12. Limitations

- No protection against block-level replay by a snapshot attacker. A stored `[nonce | ciphertext | tag]` unit captured from an older file state can be substituted back undetected. Closing this requires per-block version tracking, deferred to a future phase.
- No protection against full file rollback
- No crash consistency guarantees
- No journaling or atomic writes