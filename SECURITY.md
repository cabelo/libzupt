# Security policy and boundaries

## Supported versions and reporting

Version 2.0.0 is a release candidate with a breaking format update. Do not
claim an independent cryptographic audit, CAVP/CMVP certification, FIPS 140-3
validation or CNSA 2.0 compliance on the basis of its regression tests.
The v1 format is supported only by the explicit digest-checked migration API;
new encryption never writes v1.

Report suspected vulnerabilities privately to **alessandro.faria@owasp.org**
or **cabelo@opensuse.org**. Include the affected version/commit, compiler,
platform and a minimal reproduction using test data. Do not include real
private keys, personal information or confidential customer plaintext.
Avoid public exploit details until the maintainer has assessed the report.
Acknowledgement and remediation depend on maintainer availability; no
unfunded response-time guarantee is implied.

## Cryptographic design

* ML-KEM-768 targets the final FIPS 203 algorithm, security category 3.
  Its public key, private key, ciphertext and shared-secret sizes are
  1,184 / 2,400 / 1,088 / 32 bytes respectively.
* X25519 is a classical component. All-zero ECDH results are rejected.
* The application-specific v2 KDF hashes the concatenated component secrets
  and encapsulation transcript under a v2 context. It is not an assertion of
  equivalence to Signal PQXDH, Apple PQ3, or an IETF hybrid protocol.
* AES-256-CTR encrypts block payloads. HMAC-SHA256 authenticates each block.
  A separately derived HMAC key authenticates the complete envelope,
  including its encryption header, declared length and all block records.
* Normal decryption verifies the complete envelope tag before parsing record
  lengths or returning plaintext. The full plaintext length must match.
* Randomness comes from the OS CSPRNG. The existing void RNG API terminates
  the process if secure randomness is unavailable; no weak PRNG fallback exists.

The portable AES implementation uses an algebraic S-box rather than
secret-indexed lookup tables. On supported GCC/Clang x86 builds, a runtime
AES-NI path is selected when the CPU supports it. This removes the identified
S-box cache-index surface; it does not establish whole-library resistance to
power analysis, fault injection, speculative execution or every timing channel.
Compiler output and target-specific side-channel testing remain review work.
ACSL comments and optional Jasmin declarations are not a completed formal proof
of this release.

## Threat model

The intended property is confidentiality and tamper detection for an encrypted
message given a trusted recipient public key and protected private key.
The v2 envelope detects byte modification, block reorder/duplication,
truncation (including entire final blocks), appended data and header changes.
It does not authenticate the sender, prevent replay of a complete valid
message, provide forward secrecy, or establish public-key trust. Applications
must implement sender authentication, freshness and key distribution as needed.

Endpoint compromise, malware, a debugger reading process memory, loss of the
private key, physical attacks and a compromised compiler/dependency chain are
outside these message-format guarantees. Memory wiping is not protection
against reverse engineering. A random per-message nonce does not implement
an application replay cache.

## Legacy recovery

The v1 format used a nonstandard KEM transformation and cannot authenticate
removal of complete final blocks. `zupt_hybrid_decrypt()` rejects it.
`zupt_hybrid_decrypt_legacy()` requires the complete plaintext's expected
SHA-256 from an independent trusted source and returns no plaintext when the
digest differs. Never obtain that expected digest from attacker-controlled
metadata bundled with the ciphertext. Use [MIGRATION.md](docs/MIGRATION.md).
A missing or truncated legacy message must not be interpreted as empty data.

## Key and memory handling

The native POSIX private-key writer (`zupt_write_private_key`), used by C++,
Go, Rust, .NET and PHP key-save helpers, uses one checked descriptor with mode `0600`
and rejects symlinks, hard links, nonregular files and files owned by another
user. Use a parent directory controlled by the key owner. Windows callers must
configure directory/file ACLs. General-purpose `zupt_write_file()` is not a
secure private-key storage API; host-language save helpers must use restrictive
permissions or a platform keystore before storing private keys.

API key buffers contain plaintext key material. They are not password-protected
keystores. The archive helpers' checksummed key files have a different layout;
do not interchange them with C++/binding buffers.

`SecureBuffer` wipes owned native storage; ordinary vectors, strings, returned
plaintext and host-language copies are not automatically wiped. `mlock` /
`VirtualLock` is best effort, can fail, and does not stop a process-memory reader.
The C caller owns returned buffers: wipe plaintext/key bytes when appropriate,
then release them with `zupt_free()`, not a different runtime's allocator.

## Evidence and unresolved assurance

See [TESTING.md](docs/TESTING.md) and per-commit CI artifacts. Offline vectors,
reference comparisons, sanitizer runs, mutation tests and reproducible builds
are distinct forms of evidence, with different limits. A passing native Linux
run is not a Windows, macOS, ARM64 or complete language-binding audit.
Independent review of the hybrid construction, primitive implementations and
all deployment targets remains necessary before a high-assurance claim.
