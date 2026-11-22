/**
 * @page page-formato On-disk format
 *
 * @brief Layout of the containers and of the encrypted envelopes.
 *
 * @details
 *
 * The library has two distinct on-disk representations. The first is the
 * archival container, described by the packed header structures
 * (`zupt_archive_header_t`, `zupt_footer_t`, `zupt_index_entry_t`). The second is the
 * hybrid-key encrypted envelope, described in `docs/FORMAT.md` and
 * implemented in `src/zupt_crypto.c`. The two are not the same thing, and this
 * document describes both, with the divergences marked.
 *
 * # Archival container
 *
 * Expected sequence, according to the fields and the comments of `include/zupt.h`:
 *
 * | Region | Contents |
 * | --- | --- |
 * | Header | 64 bytes: 6-byte magic (::ZUPT_MAGIC_0 through ::ZUPT_MAGIC_5), version, global flags, timestamp, 16-byte ID, encryption header offset, comment offset, 12 reserved bytes |
 * | Data blocks | Repeated, each one with a block magic (::ZUPT_BLOCK_MAGIC_0, ::ZUPT_BLOCK_MAGIC_1), type, codec, flags and payload |
 * | Encryption header | Present when ::ZUPT_FLAG_ENCRYPTED is set; starts with the `0x03` discriminator |
 * | Index | Index block (::ZUPT_BLOCK_INDEX) with the `zupt_index_entry_t` entries |
 * | Footer | 32 bytes: index offset, total number of blocks, checksum, ASCII magic `ZEND`, version |
 *
 * All multibyte integers are little-endian. The conversion is done by the
 * inline helpers `zupt_le16_get/put`, `zupt_le32_get/put` and
 * `zupt_le64_get/put`.
 *
 * Defined block types: ::ZUPT_BLOCK_DATA (0x00), ::ZUPT_BLOCK_INDEX (0x02),
 * ::ZUPT_BLOCK_ENC_HEADER (0x03) and ::ZUPT_BLOCK_DEDUP_REF (0x04). Each data
 * block is preceded by the two magic bytes ::ZUPT_BLOCK_MAGIC_0 and
 * ::ZUPT_BLOCK_MAGIC_1.
 *
 * Codecs per block: ::ZUPT_CODEC_STORE (0x0000), ::ZUPT_CODEC_ZUPT_LZ (0x0008),
 * ::ZUPT_CODEC_ZUPT_LZH (0x0009), ::ZUPT_CODEC_ZUPT_LZHP (0x000A) and
 * ::ZUPT_CODEC_VAPTVUPT (0x0010). ::ZUPT_CODEC_AUTO (0xFFFF) requests
 * autodetection, resolved in `zupt_resolve_auto_codec()`.
 *
 * # Encrypted envelope
 *
 * It is what `docs/FORMAT.md` calls the "application format v2".
 *
 * \dotfile envelope.dot "v2 envelope layout as the code writes it (src/zupt_cxx.c:351-398)"
 *
 * The drawing above is the sequence that `zupt_hybrid_encrypt()` assembles byte
 * by byte. It does not contradict the tables below: the records there are those
 * from the C side, of `4 + n + 48` bytes (`u32le(n)` followed by `nonce(16) ‖ cifra(n) ‖ HMAC(32)`),
 * and the warning at the end of this page records that the framing described in
 * `docs/FORMAT.md` is another one.
 *
 * ## Public key (1224 bytes)
 *
 * | Offset | Field | Size |
 * | --- | --- | --- |
 * | 0 | ASCII `ZKEY` | 4 |
 * | 4 | Version `0x02` | 1 |
 * | 5 | Flags `0x00` | 1 |
 * | 6 | Reserved, zero | 2 |
 * | 8 | ML-KEM-768 encapsulation key (FIPS 203) | 1184 |
 * | 1192 | X25519 public key | 32 |
 *
 * The private key repeats the initial 1224 bytes with flags `0x01` and appends
 * the secret keys, totaling 3656 bytes. Neither of the two formats has its own
 * checksum: it is the integrity of the envelope that is authenticated.
 *
 * ## Cipher header (1137 bytes)
 *
 * | Offset | Field | Size |
 * | --- | --- | --- |
 * | 0 | Discriminator `0x03` | 1 |
 * | 1 | ML-KEM-768 ciphertext | 1088 |
 * | 1089 | Ephemeral X25519 public key | 32 |
 * | 1121 | Per-message base nonce | 16 |
 *
 * ## Records
 *
 * The plaintext is divided into records. The first eight bytes of the base nonce
 * are combined by XOR with the record identifier and the last eight act as a
 * big-endian counter. The encrypted size of a record is `12 + L + 32`; an
 * empty message produces 96 bytes. The cipher is AES-256 and the final tag has
 * 32 bytes.
 *
 * @warning `docs/FORMAT.md` describes the C++ and bindings API. The C functions
 *          `zupt_encrypt_buffer()` and `zupt_decrypt_buffer()` use the envelope
 *          `nonce(16) || cifra || HMAC(32)` described in their declarations, which
 *          is not the record format with big-endian counter above.
 *
 * @see \ref page-seguranca for the key derivation.
 */
