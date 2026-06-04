# EVL - Encrypted Virtual Locker

EVL is a block-level encrypted file container implemented in C. It provides authenticated encryption, tamper detection, and mounts as a virtual filesystem via FUSE. Any file - text, binary, video - can be stored inside an `.evl` container and accessed transparently through the mount point.

## Status

CLI and FUSE mount layer functional.

## Security Properties

| Property | Mechanism |
|---|---|
| Confidentiality | AES-256-GCM block encryption |
| Integrity | Per-block GCM authentication tag — any modification detected on read |
| Key derivation | Argon2id (memory-hard) + HKDF key separation |
| Position binding | `block_index` in AAD — block reordering detected |
| Cross-container binding | `file_id` in AAD — block transplant from another container detected |
| Nonce freshness | CSPRNG-generated 96-bit nonce per encryption including rewrites |
| Header integrity | Header authenticated separately under a derived `header_key` |

## Architecture

On-disk layout:

```
[ Header(65) | Header Nonce(12) | Header Tag(16) | Block_0 | Block_1 | ... ]

Each block: [ nonce(12) | ciphertext(block_size) | tag(16) ]
```

Key derivation chain:

```
password + salt ──► Argon2id ──► master_key
master_key ──► HKDF-Expand("EVL_ENC_KEY_v1") ──► enc_key   (block encryption)
master_key ──► HKDF-Expand("EVL_HDR_KEY_v1") ──► header_key (header authentication)
```

AAD per block:

```
AAD = file_id(16) || block_index(8, LE) || block_size(4, LE)
```

## Build

**Dependencies:** OpenSSL, libargon2, libfuse3

```bash
# Arch Linux
sudo pacman -S openssl argon2 fuse3

# Ubuntu/Debian
sudo apt install libssl-dev libargon2-dev libfuse3-dev
```

```bash
make
```

Binary at `build/evl`.

## Usage

```bash
# Create a new encrypted container
./build/evl create vault.evl

# Encrypt a file into the container
./build/evl write vault.evl secret.txt

# Decrypt and stream to stdout
./build/evl read vault.evl > recovered.txt

# Mount as a virtual filesystem
mkdir /tmp/mnt
./build/evl mount vault.evl /tmp/mnt -f
# locker.bin is now accessible transparently at /tmp/mnt/locker.bin
fusermount3 -u /tmp/mnt

# Inspect container metadata
./build/evl info vault.evl

# Verify container integrity (header authentication)
./build/evl verify vault.evl
```

Passwords are always prompted interactively via `getpass()` - never passed as CLI arguments.

## Security Testing

The following attacks have been verified to be detected:

- Ciphertext byte modification → GCM tag mismatch, read rejected
- Tag byte modification → authentication failure
- Nonce modification → tag mismatch, read rejected
- Header field tampering → header tag verification fails, file rejected
- Block transplant from another container → `file_id` mismatch in AAD, rejected
- Block reordering within same container → `block_index` mismatch in AAD, rejected
- Wrong password → header tag verification fails, file rejected

## Known Limitations

- **Block-level replay** - a snapshot attacker who captured the file at time T can substitute an old `[nonce | ciphertext | tag]` unit back into a newer file undetected. The unit is self-consistent under the same key. Preventing this requires per-block version tracking, deferred to Phase 2.
- **Full file rollback** - replacing the entire file with an older snapshot is not prevented. Requires external trusted state (TPM, remote counter).
- **Crash consistency** - partial writes may corrupt the container. No journaling or atomic write guarantees.
- **Single-file container** - one file per container in this phase. Multi-file support requires a filesystem layer.

## Documentation

- [Format Specification](docs/evl_format_v1.md)
- [Design Decisions](docs/design_decisions.md)
- [Threat Model](docs/threat_model.md)
- [Roadmap](docs/roadmap.md)