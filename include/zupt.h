/*
 * Zupt — Backup-oriented compression with AES-256 encryption
 * Copyright (c) 2026 Cristian Cezar Moisés
 * SPDX-License-Identifier: MIT
 */
#ifndef ZUPT_H
#define ZUPT_H

/* Feature test macros — must precede all system includes.
 * _DEFAULT_SOURCE gives us lstat() on glibc without -D_GNU_SOURCE. */
#if !defined(_DEFAULT_SOURCE) && !defined(_GNU_SOURCE)
  #define _DEFAULT_SOURCE 1
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#ifdef _WIN32
  #include <windows.h>
  #include <direct.h>
  #define ZUPT_PATH_SEP '\\'
  #define zupt_mkdir(p) _mkdir(p)
#else
  #include <sys/stat.h>
  #include <sys/types.h>
  #include <dirent.h>
  #include <unistd.h>
  #define ZUPT_PATH_SEP '/'
  #define zupt_mkdir(p) mkdir(p, 0755)
#endif

#define ZUPT_VERSION_STRING "1.5.0"
#define ZUPT_FORMAT_MAJOR   1
#define ZUPT_FORMAT_MINOR   4

#define ZUPT_MAGIC_0  0x5A
#define ZUPT_MAGIC_1  0x55
#define ZUPT_MAGIC_2  0x50
#define ZUPT_MAGIC_3  0x54
#define ZUPT_MAGIC_4  0x1A
#define ZUPT_MAGIC_5  0x00
#define ZUPT_BLOCK_MAGIC_0 0xBB
#define ZUPT_BLOCK_MAGIC_1 0x01

#define ZUPT_MAX_PATH         4096
#define ZUPT_MAX_FILES        2000000
#define ZUPT_DEFAULT_BLOCK_SZ (4 * 1024 * 1024)
#define ZUPT_MIN_BLOCK_SZ     (64 * 1024)
#define ZUPT_MAX_BLOCK_SZ     (256 * 1024 * 1024)

/* Global flags */
#define ZUPT_FLAG_ENCRYPTED    (1u << 0)
#define ZUPT_FLAG_CKSUM_XXH64  (0u << 5)
#define ZUPT_FLAG_SOLID        (1u << 1)
#define ZUPT_FLAG_MULTITHREADED (1u << 2) /* Informational: archive was produced with MT */
#define ZUPT_FLAG_PQ_HYBRID    (1u << 3) /* Post-quantum hybrid encryption */
#define ZUPT_FLAG_FORMAT_STABLE (1u << 4) /* v1.0: format frozen */

/* Encryption types (stored in encryption header block) */
#define ZUPT_ENC_PBKDF2     0x01  /* Password-based: PBKDF2 → AES-256-CTR + HMAC */
#define ZUPT_ENC_PQ_HYBRID  0x02  /* ML-KEM-768 + X25519 hybrid KEM */

/* Block types */
#define ZUPT_BLOCK_DATA       0x00
#define ZUPT_BLOCK_INDEX      0x02
#define ZUPT_BLOCK_ENC_HEADER 0x03

/* Block flags */
#define ZUPT_BFLAG_ENCRYPTED  (1u << 0)

/* Codec IDs */
#define ZUPT_CODEC_STORE   0x0000
#define ZUPT_CODEC_ZUPT_LZ 0x0008
#define ZUPT_CODEC_ZUPT_LZH 0x0009  /* LZ77 + Huffman */
#define ZUPT_CODEC_ZUPT_LZHP 0x000A /* LZ77 + Huffman + Byte Prediction (default) */

/* Crypto */
#define ZUPT_SALT_SIZE       32
#define ZUPT_NONCE_SIZE      16
#define ZUPT_HMAC_SIZE       32
#define ZUPT_AES_KEY_SIZE    32
#define ZUPT_KDF_ITERATIONS  600000

typedef enum {
    ZUPT_OK = 0, ZUPT_ERR_IO = -1, ZUPT_ERR_CORRUPT = -2,
    ZUPT_ERR_BAD_MAGIC = -3, ZUPT_ERR_BAD_VERSION = -4,
    ZUPT_ERR_BAD_CHECKSUM = -5, ZUPT_ERR_NOMEM = -6,
    ZUPT_ERR_OVERFLOW = -7, ZUPT_ERR_INVALID = -8,
    ZUPT_ERR_NOT_FOUND = -9, ZUPT_ERR_UNSUPPORTED = -10,
    ZUPT_ERR_AUTH_FAIL = -11,
} zupt_error_t;

/* ─── On-disk (packed LE) ─── */
#pragma pack(push, 1)
typedef struct {
    uint8_t  magic[6];
    uint8_t  version_major, version_minor;
    uint32_t global_flags;
    uint64_t creation_time;
    uint8_t  archive_id[16];
    uint64_t encryption_header_off;
    uint64_t comment_offset;
    uint8_t  reserved[12];
} zupt_archive_header_t; /* 64 bytes */

typedef struct {
    uint64_t index_offset;
    uint64_t total_blocks;
    uint64_t archive_checksum;
    uint8_t  footer_magic[4]; /* "ZEND" */
    uint32_t footer_version;
} zupt_footer_t; /* 32 bytes */
#pragma pack(pop)

/* ─── In-memory ─── */
typedef struct {
    char path[ZUPT_MAX_PATH];
    uint64_t uncompressed_size, compressed_size;
    uint64_t modification_time, content_hash;
    uint64_t first_block_offset;
    uint32_t block_count, attributes;
} zupt_index_entry_t;

typedef struct {
    uint8_t block_type; uint16_t codec_id, block_flags;
    uint64_t uncompressed_size, compressed_size, checksum;
    uint8_t *payload;
} zupt_block_t;

typedef struct {
    uint8_t enc_key[ZUPT_AES_KEY_SIZE];
    uint8_t mac_key[ZUPT_HMAC_SIZE];
    uint8_t salt[ZUPT_SALT_SIZE];
    uint8_t base_nonce[ZUPT_NONCE_SIZE];
    uint32_t iterations;
    int active;
} zupt_keyring_t;

typedef struct {
    char **paths, **arc_paths;
    int count, capacity;
} zupt_filelist_t;

typedef struct {
    int level; uint32_t block_size; uint16_t codec_id;
    int verbose, encrypt, quiet, solid, threads;
    int pq_mode;           /* 1 = post-quantum hybrid KEM mode */
    char password[256];
    char keyfile[ZUPT_MAX_PATH]; /* Path to .zupt-key file */
    zupt_keyring_t keyring;
} zupt_options_t;

/* ═══════════════════════════════════════════════════════════════════
 * PORTABLE LITTLE-ENDIAN SERIALIZATION
 *
 * All multi-byte fields in the on-disk format are stored as LE.
 * These helpers ensure correct behaviour on both LE and BE hosts.
 * ═══════════════════════════════════════════════════════════════════ */

static inline void zupt_le16_put(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
}
static inline void zupt_le32_put(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}
static inline void zupt_le64_put(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) { p[i] = (uint8_t)(v & 0xFF); v >>= 8; }
}
static inline uint16_t zupt_le16_get(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}
static inline uint32_t zupt_le32_get(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static inline uint64_t zupt_le64_get(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

/* ═══════════════════════════════════════════════════════════════════
 * SECURE MEMORY WIPE (resists dead-store elimination by compilers)
 * ═══════════════════════════════════════════════════════════════════ */

static inline void zupt_secure_wipe(void *ptr, size_t len) {
#if defined(_WIN32)
    SecureZeroMemory(ptr, len);
#elif (defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25)))
    extern void explicit_bzero(void *, size_t);
    explicit_bzero(ptr, len);
#elif defined(__FreeBSD__) || defined(__OpenBSD__)
    extern void explicit_bzero(void *, size_t);
    explicit_bzero(ptr, len);
#else
    volatile uint8_t *vp = (volatile uint8_t *)ptr;
    for (size_t i = 0; i < len; i++) vp[i] = 0;
#endif
}

/* ═══════════════════════════════════════════════════════════════════
 * REGULAR-FILE CHECK (skip symlinks, devices, FIFOs, sockets)
 * ═══════════════════════════════════════════════════════════════════ */

static inline int zupt_is_regular_file(const char *path) {
#ifdef _WIN32
    DWORD attr = GetFileAttributesA(path);
    if (attr == INVALID_FILE_ATTRIBUTES) return 0;
    return !(attr & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DEVICE |
                     FILE_ATTRIBUTE_REPARSE_POINT));
#else
    struct stat st;
    if (lstat(path, &st) != 0) return 0;
    return S_ISREG(st.st_mode);
#endif
}

/* ─── Solid-mode compression ─── */
zupt_error_t zupt_compress_solid(const char *out, const char **arc, const char **disk, int n, zupt_options_t *opts);

/* ─── SHA-256 ─── */
typedef struct { uint32_t state[8]; uint64_t count; uint8_t buf[64]; } zupt_sha256_ctx;
void zupt_sha256_init(zupt_sha256_ctx *c);
void zupt_sha256_update(zupt_sha256_ctx *c, const uint8_t *d, size_t n);
void zupt_sha256_final(zupt_sha256_ctx *c, uint8_t h[32]);
void zupt_sha256(const uint8_t *d, size_t n, uint8_t h[32]);

/* ─── AES-256 ─── */
typedef struct { uint32_t rk[60]; } zupt_aes256_ctx;
void zupt_aes256_init(zupt_aes256_ctx *c, const uint8_t key[32]);
void zupt_aes256_encrypt_block(const zupt_aes256_ctx *c, const uint8_t in[16], uint8_t out[16]);

/* ─── Crypto ops ─── */
void zupt_hmac_sha256(const uint8_t *key, size_t klen, const uint8_t *data, size_t dlen, uint8_t mac[32]);
void zupt_pbkdf2_sha256(const uint8_t *pw, size_t pwlen, const uint8_t *salt, size_t slen, uint32_t iter, uint8_t *out, size_t olen);
void zupt_aes256_ctr(const uint8_t key[32], const uint8_t nonce[16], const uint8_t *in, uint8_t *out, size_t len);
void zupt_derive_keys(zupt_keyring_t *kr, const char *pw, const uint8_t salt[32], const uint8_t nonce[16], uint32_t iter);
uint8_t *zupt_encrypt_buffer(const zupt_keyring_t *kr, const uint8_t *plain, size_t plen, uint64_t seq, size_t *olen);
uint8_t *zupt_decrypt_buffer(const zupt_keyring_t *kr, const uint8_t *pkg, size_t pkglen, uint64_t seq, size_t *olen);
void zupt_random_bytes(uint8_t *buf, size_t len);

/* ─── XXH64 ─── */
uint64_t zupt_xxh64(const void *data, size_t len, uint64_t seed);

/* ─── LZ ─── */
size_t zupt_lz_compress(const uint8_t *src, size_t slen, uint8_t *dst, size_t dcap, int level);
size_t zupt_lz_decompress(const uint8_t *src, size_t slen, uint8_t *dst, size_t dlen);
size_t zupt_lz_bound(size_t slen);

/* ─── LZH (LZ77 + Huffman) ─── */
size_t zupt_lzh_compress(const uint8_t *src, size_t slen, uint8_t *dst, size_t dcap, int level);
size_t zupt_lzh_decompress(const uint8_t *src, size_t slen, uint8_t *dst, size_t dlen);
size_t zupt_lzh_bound(size_t slen);

/* ─── Byte Prediction (order-1 context transform) ─── */
void  zupt_predict_build(const uint8_t *data, size_t len, uint8_t prediction[256]);
void  zupt_predict_encode(const uint8_t *in, uint8_t *out, size_t len, const uint8_t pred[256]);
void  zupt_predict_decode(const uint8_t *in, uint8_t *out, size_t len, const uint8_t pred[256]);
float zupt_predict_benefit(const uint8_t *data, size_t len);

/* ─── Format I/O ─── */
int zupt_write_varint(FILE *f, uint64_t v);
int zupt_read_varint(FILE *f, uint64_t *v);
int zupt_encode_varint(uint8_t *b, uint64_t v);
int zupt_decode_varint(const uint8_t *b, size_t blen, uint64_t *v);

void zupt_filelist_init(zupt_filelist_t *fl);
void zupt_filelist_free(zupt_filelist_t *fl);
void zupt_filelist_add(zupt_filelist_t *fl, const char *disk_path, const char *arc_path);
void zupt_collect_files(zupt_filelist_t *fl, const char *path, const char *base);

zupt_error_t zupt_compress_files(const char *out, const char **arc, const char **disk, int n, zupt_options_t *opts);
zupt_error_t zupt_extract_archive(const char *arc, const char *dir, zupt_options_t *opts);
zupt_error_t zupt_list_archive(const char *arc, zupt_options_t *opts);
zupt_error_t zupt_test_archive(const char *arc, zupt_options_t *opts);

/* ─── Hybrid PQ KEM (ML-KEM-768 + X25519) ─── */
int zupt_hybrid_keygen(const char *keyfile);
int zupt_hybrid_export_pubkey(const char *privfile, const char *pubfile);
int zupt_hybrid_encrypt_init(zupt_keyring_t *kr, const char *pubkeyfile,
                              uint8_t *enc_hdr, size_t *enc_hdr_len);
int zupt_hybrid_decrypt_init(zupt_keyring_t *kr, const char *privkeyfile,
                              const uint8_t *enc_hdr, size_t enc_hdr_len);

const char *zupt_strerror(zupt_error_t e);
const char *zupt_codec_name(uint16_t id);
void zupt_default_options(zupt_options_t *o);
void zupt_format_size(uint64_t bytes, char *buf, size_t cap);

#endif
