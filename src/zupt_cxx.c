/*
 * libzupt - C wrapper for hybrid post-quantum encryption
 * C implementation for C++ library
 *
 * SPDX-License-Identifier: MIT
 */

/**
 * @file  src/zupt_cxx.c
 * @brief Implementação do "shim" C da API híbrida (`zupt_cxx.h`): geração de
 *        chaves, E/S de arquivos e cifra/decifra de envelopes.
 * @details Este é o TU que a camada C++ (`include/zupt.hpp`) e os bindings
 *          (Python, Node, Java) chamam para atravessar a fronteira C.
 *
 *          <b>Propriedade de memória</b>: todo ponteiro devolvido por estas
 *          funções (`zupt_read_file`, `zupt_hybrid_encrypt`,
 *          `zupt_hybrid_decrypt`, `zupt_hybrid_decrypt_legacy`) foi alocado
 *          com `malloc()` aqui e deve ser liberado com `zupt_free()`. As
 *          funções que devolvem `int` escrevem apenas nos buffers que o
 *          chamador fornece (`pub_key`, `priv_key`, `enc_header`), sem alocação
 *          própria.
 *
 *          <b>Formatos</b>: chaves usam o contêiner `ZKEY` (mágica + versão +
 *          flags + `ml_pk` 1184 + `x_pk` 32 [+ `ml_sk` 2400 + `x_sk` 32]) e os
 *          envelopes usam `ZUP2` (v2). O caminho legado v1 existe apenas em
 *          `zupt_hybrid_decrypt_legacy()`.
 *
 *          <b>Erros</b>: todas as falhas se acumulam num único valor de
 *          retorno (`NULL` ou `-1`); o código interno (CSPRNG, chave rejeitada,
 *          autenticação, E/S) não é reportado ao chamador.
 *
 *          <b>Concorrência</b>: não há mutex nem proteção alguma neste arquivo;
 *          cada chamada usa estado local, mas a segurança de uso simultâneo
 *          depende das funções do lado C (`zupt_mlkem*`, `zupt_x25519*`,
 *          as funções `zupt_hybrid_*_init_mem`), que também não documentam restrição.
 */

/* Darwin hides O_NOFOLLOW in strict POSIX mode. Request its extensions before
 * any system header so private-key writes keep rejecting symbolic links. */
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif
#ifndef _POSIX_C_SOURCE
/**
 * @brief Macro de teste de recursos POSIX exigido por este TU.
 * @details `O_NOFOLLOW` (rejeição de symlink na escrita de chave privada) só
 *          existe com o perfil POSIX exposto; em modo POSIX estrito o cabeçalho
 *          `<fcntl.h>` pode escondê-lo. O valor `200809L` é o perfil do
 *          SUSv4/IEEE 1003.1-2008. Em Windows este macro não é usado.
 */
#define _POSIX_C_SOURCE 200809L
#endif
#include "zupt_cxx.h"
#include "zupt.h"
#include "zupt_mlkem.h"
#include "zupt_x25519.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

// Definição: free() puro. O cabeçalho exige zupt_free() como o único meio de
// liberar memória devolvida por este TU, para manter a fronteira de CRT dos
// bindings explícita.
void zupt_free(void* ptr) { free(ptr); }

/* ═══════════════════════════════════════════════════════════════════
 * KEY GENERATION
 * ═══════════════════════════════════════════════════════════════════ */

int zupt_hybrid_keygen_c(uint8_t* pub_key, uint8_t* priv_key) {
    if (!pub_key || !priv_key) return -1;

    uint8_t ml_pk[MLKEM_PUBLICKEYBYTES];
    uint8_t ml_sk[MLKEM_SECRETKEYBYTES];
    uint8_t x_sk[32], x_pk[32];

    /* Generate ML-KEM-768 keypair */
    if (zupt_mlkem768_keygen(ml_pk, ml_sk) != 0) {
        return -1;
    }

    /* Generate X25519 keypair */
    zupt_random_bytes(x_sk, 32);
    zupt_x25519_base(x_pk, x_sk);

    /* Build public key: ZKEY header + ml_pk + x_pk */
    memcpy(pub_key, "ZKEY", 4);
    pub_key[4] = ZUPT_KEY_FORMAT_VERSION; /* version */
    pub_key[5] = 0x00; /* no private key */
    pub_key[6] = pub_key[7] = 0;
    memcpy(pub_key + 8, ml_pk, 1184);
    memcpy(pub_key + 8 + 1184, x_pk, 32);

    /* Build private key: ZKEY header + ml_pk + x_pk + ml_sk + x_sk */
    memcpy(priv_key, "ZKEY", 4);
    priv_key[4] = ZUPT_KEY_FORMAT_VERSION; /* version */
    priv_key[5] = 0x01; /* has private key */
    priv_key[6] = priv_key[7] = 0;
    memcpy(priv_key + 8, ml_pk, 1184);
    memcpy(priv_key + 8 + 1184, x_pk, 32);
    memcpy(priv_key + 8 + 1184 + 32, ml_sk, 2400);
    memcpy(priv_key + 8 + 1184 + 32 + 2400, x_sk, 32);

    /* Wipe temporary keys */
    zupt_secure_wipe(ml_sk, sizeof(ml_sk));
    zupt_secure_wipe(x_sk, 32);

    return 0;
}

int zupt_hybrid_export_pubkey_c(const uint8_t* priv_key, uint8_t* pub_key) {
    if (!priv_key || !pub_key) return -1;

    /* Validate private key header */
    if (memcmp(priv_key, "ZKEY", 4) != 0) return -1;
    if ((priv_key[4] != 1 && priv_key[4] != ZUPT_KEY_FORMAT_VERSION) ||
        priv_key[5] != 1 || priv_key[6] || priv_key[7]) return -1;

    /* Extract public key data */
    const uint8_t* ml_pk = priv_key + 8;
    const uint8_t* x_pk = ml_pk + 1184;

    /* Build public key */
    memcpy(pub_key, "ZKEY", 4);
    pub_key[4] = priv_key[4]; /* preserve the source format */
    pub_key[5] = 0x00;
    pub_key[6] = pub_key[7] = 0;
    memcpy(pub_key + 8, ml_pk, 1184);
    memcpy(pub_key + 8 + 1184, x_pk, 32);

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * FILE I/O
 * ═══════════════════════════════════════════════════════════════════ */

uint8_t* zupt_read_file(const char* path, size_t* size) {
    if (!path || !size) return NULL;

    FILE* f = fopen(path, "rb");
    if (!f) return NULL;

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }

    long file_size = ftell(f);
    if (file_size < 0) {
        fclose(f);
        return NULL;
    }
    *size = (size_t)file_size;

    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }

    uint8_t* buf = (uint8_t*)malloc(*size ? *size : 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }

    size_t read_size = fread(buf, 1, *size, f);
    fclose(f);

    if (read_size != *size) {
        free(buf);
        return NULL;
    }

    return buf;
}

int zupt_write_file(const char* path, const uint8_t* data, size_t size) {
    if (!path || (!data && size > 0)) return -1;

    FILE* f = fopen(path, "wb");
    if (!f) return -1;

    size_t written = fwrite(data, 1, size, f);
    int closed = fclose(f);
    return (written == size && closed == 0) ? 0 : -1;
}

int zupt_write_private_key(const char* path, const uint8_t* data, size_t size) {
    if (!path || !data || size != 3656 || memcmp(data, "ZKEY", 4) != 0 ||
        (data[4] != 1 && data[4] != ZUPT_KEY_FORMAT_VERSION) ||
        data[5] != 1 || data[6] || data[7]) return -1;
#ifndef _WIN32
    int fd = open(path, O_WRONLY | O_CREAT | O_NOFOLLOW | O_NONBLOCK, 0600);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1 ||
        st.st_uid != geteuid() || fchmod(fd, 0600) != 0 || ftruncate(fd, 0) != 0) {
        close(fd);
        return -1;
    }
    FILE* file = fdopen(fd, "wb");
    if (!file) { close(fd); return -1; }
    size_t written = fwrite(data, 1, size, file);
    int closed = fclose(file);
    return written == size && closed == 0 ? 0 : -1;
#else
    return zupt_write_file(path, data, size);
#endif
}

/* ═══════════════════════════════════════════════════════════════════
 * HYBRID ENCRYPTION/DECRYPTION
 * ═══════════════════════════════════════════════════════════════════ */

/* v2 envelope: "ZUP2" || u64le(plaintext bytes) || block records || HMAC.
 * The final MAC binds the entire encryption header and complete record stream.
 * Authenticate this MAC before parsing lengths or returning any plaintext. */
/**
 * @name Envelope v2 (`ZUP2`)
 * Constantes de empacotamento usadas por `zupt_hybrid_encrypt()`,
 * `zupt_hybrid_decrypt()` e `decrypt_records()`.
 *
 * O envelope é `"ZUP2"` ‖ `u64le(tamanho do texto em claro)` ‖ registros ‖
 * tag final. Cada registro ocupa `4 + n + 48` bytes (comprimento little-endian
 * de 4 bytes, seguido do envelope de 48 bytes do lado C: nonce 16 + texto
 * cifrado `n` + MAC 32). Autenticar a tag final antes de interpretar qualquer
 * comprimento é requisito do desenho: os comprimentos são dados do agressor.
 * @{
 */
/*! Tamanho máximo de um bloco de texto em claro dentro do envelope, em bytes
 *  (4 MiB). O texto em claro é dividido em blocos deste tamanho e cada bloco
 *  recebe um envelope próprio de 52 bytes, o que limita o custo de autenticação
 *  antes de liberar o primeiro byte decifrado. A mesma constante é usada na
 *  leitura (`zupt_hybrid_decrypt`) para rejeitar registros anunciados com
 *  comprimento maior. */
#define ZUPT_ENCRYPT_BLOCK_SIZE (4 * 1024 * 1024)
/*! Tamanho do cabeçalho do envelope, em bytes: os 4 bytes de `"ZUP2"` mais os
 *  8 bytes de `u64le` com o comprimento do texto em claro. */
#define ENVELOPE_PREFIX 12
/*! Tamanho da tag de autenticação final do envelope, em bytes. */
#define ENVELOPE_TAG 32
/** @} */

/**
 * @brief Deriva o keyring para decifrar envelopes do formato legado v1.
 * @details Definida em `src/zupt_crypto.c`. Não está declarada em
 *          `include/zupt.h`: a declaração `extern` abaixo é o único ponto pelo
 *          qual este TU a enxerga, e o protótipo daqui não é conferido contra a
 *          definição por nenhum cabeçalho compartilhado (ver arquivo de
 *          achados). O comportamento descrito aqui foi lido da definição:
 *          analisa e valida a chave privada em buffer, invoca o núcleo de
 *          decifração em modo legado (KDF v1) e apaga as chaves temporárias.
 *
 * Os cinco parâmetros desta declaração `extern` são anônimos no código-fonte,
 * então são descritos aqui em ordem: `kr`, o keyring a preencher (capacidade de
 * `sizeof(zupt_keyring_t)`); `priv_key`, a chave privada serializada `ZKEY`;
 * `priv_key_len`, o tamanho de `priv_key`; `enc_header`, o cabeçalho de cifra
 * legado; `enc_header_len`, o tamanho de `enc_header`, que deve ser 1137.
 * @return `0` em sucesso; diferente de zero em falha (`-1` quando a chave
 *         privada é rejeitada, ou o código devolvido pelo núcleo de decifração).
 */
extern int zupt_hybrid_decrypt_init_legacy_mem(zupt_keyring_t *,
    const uint8_t *, size_t, const uint8_t *, size_t);

/**
 * @brief Descarta texto em claro intermediário: apaga e libera.
 * @details Se `p` for `NULL`, nada acontece (nem o `free`). Quando `p` é não
 *          nulo, apaga `len` bytes com `zupt_secure_wipe()` e chama `free()`
 *          — não `zupt_free()`, embora este TU seja a fronteira de alocação.
 * @param[in] p   Buffer a descartar (propriedade de quem chama).
 * @param[in] len Quantidade de bytes a apagar; deve ser o tamanho útil do
 *                buffer, e não o tamanho alocado.
 * @return Nada.
 */
static void discard_plain(uint8_t *p, size_t len) {
    if (p) { zupt_secure_wipe(p, len); free(p); }
}

/**
 * @brief Calcula a tag final de um envelope v2 sobre o cabeçalho e os registros.
 * @details Construção HMAC-SHA256 feita à mão neste TU (não usa
 *          `zupt_hmac_sha256` para a etapa externa):
 *          1. `outer_key = HMAC-SHA256(kr->mac_key, "libzupt/envelope/key/v2")`;
 *          2. `inner = SHA256((outer_key ^ 0x36, 64 bytes) ‖ "libzupt/envelope/v2" ‖
 *             header[0..1136] ‖ records[0..len-1])`;
 *          3. `tag = SHA256((outer_key ^ 0x5c, 64 bytes) ‖ inner)`.
 *          Os dois domínios de separação estão fixos no código; alterá-los
 *          quebra a interoperabilidade com envelopes já gravados.
 *          Antes do retorno, `pad`, `inner`, `outer_key` e o contexto SHA-256
 *          são apagados com `zupt_secure_wipe()`.
 * @warning `header` é lido em 1137 bytes fixos, sem qualquer verificação: o
 *          buffer deve ter essa capacidade. Nenhum dos ponteiros é testado
 *          contra `NULL` aqui — a validação é responsabilidade de quem chama.
 * @param[in]  kr      Keyring ativo (só `mac_key` é usada).
 * @param[in]  header  Cabeçalho de cifra completo (1137 bytes).
 * @param[in]  records Sequência de registros, contígua.
 * @param[in]  len     Tamanho de `records`, em bytes.
 * @param[out] tag     Onde escrever os 32 bytes da tag.
 * @return Nada.
 */
static void envelope_tag(const zupt_keyring_t *kr, const uint8_t header[1137],
                         const uint8_t *records, size_t len, uint8_t tag[32]) {
    static const uint8_t domain[] = "libzupt/envelope/v2";
    static const uint8_t key_domain[] = "libzupt/envelope/key/v2";
    uint8_t pad[64], inner[32], outer_key[32];
    zupt_hmac_sha256(kr->mac_key, 32, key_domain, sizeof(key_domain) - 1, outer_key);
    zupt_sha256_ctx ctx;
    memset(pad, 0x36, sizeof(pad));
    for (size_t i = 0; i < 32; ++i) pad[i] ^= outer_key[i];
    zupt_sha256_init(&ctx);
    zupt_sha256_update(&ctx, pad, sizeof(pad));
    zupt_sha256_update(&ctx, domain, sizeof(domain) - 1);
    zupt_sha256_update(&ctx, header, 1137);
    zupt_sha256_update(&ctx, records, len);
    zupt_sha256_final(&ctx, inner);
    memset(pad, 0x5c, sizeof(pad));
    for (size_t i = 0; i < 32; ++i) pad[i] ^= outer_key[i];
    zupt_sha256_init(&ctx);
    zupt_sha256_update(&ctx, pad, sizeof(pad));
    zupt_sha256_update(&ctx, inner, sizeof(inner));
    zupt_sha256_final(&ctx, tag);
    zupt_secure_wipe(pad, sizeof(pad));
    zupt_secure_wipe(inner, sizeof(inner));
    zupt_secure_wipe(outer_key, sizeof(outer_key));
    zupt_secure_wipe(&ctx, sizeof(ctx));
}

/**
 * @brief Compara duas tags de 32 bytes sem interromper no primeiro byte diferente.
 * @details Acumula em `uint32_t` o OR dos XORs byte a byte e devolve
 *          `diff == 0`. O laço percorre os 32 bytes inteiros, o que evita o
 *          padrão de ramo de uma comparação ingênua; não há aqui nenhuma
 *          garantia formal de tempo constante (a primitiva verificada por
 *          Jasmin, `zupt_mac_verify_ct`, fica no lado C).
 * @param[in] a Primeira tag (32 bytes legíveis).
 * @param[in] b Segunda tag (32 bytes legíveis).
 * @return `1` se as tags são iguais, `0` caso contrário.
 */
static int same_tag(const uint8_t a[32], const uint8_t b[32]) {
    uint32_t diff = 0;
    for (size_t i = 0; i < 32; ++i) diff |= a[i] ^ b[i];
    return diff == 0;
}

uint8_t* zupt_hybrid_encrypt(const uint8_t* pub_key, size_t pub_key_len,
    const uint8_t* plaintext, size_t plaintext_len,
    uint8_t* enc_header, size_t* enc_header_len, size_t* ciphertext_len) {
    if (ciphertext_len) *ciphertext_len = 0;
    if (enc_header_len) *enc_header_len = 0;
    if (!pub_key || !enc_header || !enc_header_len || !ciphertext_len ||
        (!plaintext && plaintext_len)) return NULL;
    size_t blocks = plaintext_len ? 1 + (plaintext_len - 1) / ZUPT_ENCRYPT_BLOCK_SIZE : 1;
    if (plaintext_len > SIZE_MAX - ENVELOPE_PREFIX - ENVELOPE_TAG ||
        blocks > (SIZE_MAX - ENVELOPE_PREFIX - ENVELOPE_TAG - plaintext_len) / 52)
        return NULL;
    size_t total = ENVELOPE_PREFIX + plaintext_len + blocks * 52 + ENVELOPE_TAG;
    uint8_t *out = (uint8_t *)malloc(total);
    if (!out) return NULL;
    zupt_keyring_t kr = {0};
    if (zupt_hybrid_encrypt_init_mem(&kr, pub_key, pub_key_len,
                                    enc_header, enc_header_len) != 0) {
        zupt_munlock_keys(&kr, sizeof(kr));
        free(out);
        return NULL;
    }
    memcpy(out, "ZUP2", 4);
    zupt_le64_put(out + 4, (uint64_t)plaintext_len);
    size_t source = 0, dest = ENVELOPE_PREFIX;
    for (size_t block = 0; block < blocks; ++block) {
        size_t n = plaintext_len - source;
        if (n > ZUPT_ENCRYPT_BLOCK_SIZE) n = ZUPT_ENCRYPT_BLOCK_SIZE;
        size_t encrypted_len = 0;
        uint8_t *encrypted = zupt_encrypt_buffer(&kr,
            plaintext ? plaintext + source : NULL, n, block, &encrypted_len);
        if (!encrypted || encrypted_len != n + 48) {
            free(encrypted);
            zupt_munlock_keys(&kr, sizeof(kr));
            free(out);
            *enc_header_len = 0;
            return NULL;
        }
        for (unsigned i = 0; i < 4; ++i) out[dest + i] = (uint8_t)(n >> (8 * i));
        memcpy(out + dest + 4, encrypted, encrypted_len);
        free(encrypted);
        source += n;
        dest += n + 52;
    }
    envelope_tag(&kr, enc_header, out, dest, out + dest);
    zupt_munlock_keys(&kr, sizeof(kr));
    *ciphertext_len = total;
    return out;
}

/**
 * @brief Decifra a sequência de registros de um envelope, validando cada
 *        comprimento antes de usá-lo.
 * @details Usada por `zupt_hybrid_decrypt()` (sobre o envelope v2, já
 *          autenticado pela tag final) e por `zupt_hybrid_decrypt_legacy()`
 *          (sobre o pacote v1, cuja integridade vem do SHA-256 conferido depois).
 *          Per registro: exige pelo menos 52 bytes restantes; lê o
 *          comprimento `n` em little-endian de 4 bytes; rejeita `n` maior que
 *          `ZUPT_ENCRYPT_BLOCK_SIZE`, maior que o espaço ainda esperado, ou que
 *          não caiba no restante do pacote; rejeita `n == 0` exceto quando é o
 *          único registro de um pacote de exatamente 52 bytes. Decifra os
 *          `n + 48` bytes seguintes com `zupt_decrypt_buffer()` usando o índice
 *          do registro como `block_seq` (isso vincula o MAC de cada registro à
 *          sua posição) e exige que o resultado tenha exatamente `n` bytes.
 *          Qualquer desvio salta para o rótulo `fail`, que apaga o buffer de
 *          saída com `discard_plain()` e devolve `NULL` sem escrever
 *          `*plaintext_len`.
 * @param[in]  kr             Keyring derivado do cabeçalho de cifra.
 * @param[in]  ciphertext     Início da sequência de registros (sem o prefixo
 *                            `ZUP2` no caso v2).
 * @param[in]  ciphertext_len Tamanho total da sequência.
 * @param[in]  expected_len   Total de bytes de texto em claro esperado. No
 *                            v2 vem do campo `u64le` do envelope; no v1 é
 *                            somado pela varredura de registros.
 * @param[out] plaintext_len  Recebe o total decifrado, somente no sucesso.
 * @return Buffer `malloc`'d de `expected_len` bytes (1 byte alocado quando
 *         `expected_len == 0`), de propriedade de quem chama; liberar com
 *         `zupt_free()`.
 * @retval NULL pacote curto demais (`ciphertext_len < 52`), `expected_len`
 *              maior que o pacote, registro fora dos limites, falha de
 *              decifra/autenticação de um registro, total diferente do
 *              esperado, ou `malloc` falho.
 */
static uint8_t *decrypt_records(zupt_keyring_t *kr, const uint8_t *ciphertext,
    size_t ciphertext_len, size_t expected_len, size_t *plaintext_len) {
    if (ciphertext_len < 52 || expected_len > ciphertext_len) return NULL;
    uint8_t *plaintext = (uint8_t *)malloc(expected_len ? expected_len : 1);
    if (!plaintext) return NULL;
    size_t pos = 0, total = 0;
    uint64_t block = 0;
    while (pos < ciphertext_len) {
        if (ciphertext_len - pos < 52) goto fail;
        uint32_t n = (uint32_t)ciphertext[pos] |
            ((uint32_t)ciphertext[pos + 1] << 8) |
            ((uint32_t)ciphertext[pos + 2] << 16) |
            ((uint32_t)ciphertext[pos + 3] << 24);
        if (n > ZUPT_ENCRYPT_BLOCK_SIZE || n > expected_len - total ||
            (n == 0 && (pos != 0 || ciphertext_len != 52)) ||
            (size_t)n + 52 > ciphertext_len - pos) goto fail;
        size_t decoded_len = 0;
        uint8_t *decoded = zupt_decrypt_buffer(kr, ciphertext + pos + 4,
                                               (size_t)n + 48, block, &decoded_len);
        if (!decoded || decoded_len != n) {
            discard_plain(decoded, decoded_len);
            goto fail;
        }
        if (n) memcpy(plaintext + total, decoded, n);
        discard_plain(decoded, decoded_len);
        total += n;
        pos += (size_t)n + 52;
        ++block;
    }
    if (total != expected_len) goto fail;
    *plaintext_len = total;
    return plaintext;
fail:
    discard_plain(plaintext, expected_len);
    return NULL;
}

uint8_t* zupt_hybrid_decrypt(const uint8_t* priv_key, size_t priv_key_len,
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* enc_header, size_t enc_header_len, size_t* plaintext_len) {
    if (plaintext_len) *plaintext_len = 0;
    if (!priv_key || !ciphertext || !enc_header || !plaintext_len ||
        enc_header_len != 1137 || enc_header[0] != ZUPT_ENVELOPE_FORMAT ||
        ciphertext_len < ENVELOPE_PREFIX + 52 + ENVELOPE_TAG ||
        memcmp(ciphertext, "ZUP2", 4) != 0) return NULL;
    zupt_keyring_t kr = {0};
    if (zupt_hybrid_decrypt_init_mem(&kr, priv_key, priv_key_len,
                                    enc_header, enc_header_len) != 0) {
        zupt_munlock_keys(&kr, sizeof(kr));
        return NULL;
    }
    uint8_t tag[32];
    envelope_tag(&kr, enc_header, ciphertext, ciphertext_len - ENVELOPE_TAG, tag);
    int authenticated = same_tag(tag, ciphertext + ciphertext_len - ENVELOPE_TAG);
    zupt_secure_wipe(tag, sizeof(tag));
    uint8_t *plaintext = NULL;
    if (authenticated) {
        uint64_t expected = zupt_le64_get(ciphertext + 4);
        size_t record_len = ciphertext_len - ENVELOPE_PREFIX - ENVELOPE_TAG;
        if (expected <= SIZE_MAX && expected <= record_len)
            plaintext = decrypt_records(&kr, ciphertext + ENVELOPE_PREFIX,
                record_len, (size_t)expected, plaintext_len);
    }
    zupt_munlock_keys(&kr, sizeof(kr));
    return plaintext;
}

uint8_t* zupt_hybrid_decrypt_legacy(const uint8_t* priv_key, size_t priv_key_len,
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* enc_header, size_t enc_header_len,
    const uint8_t expected_sha256[32], size_t* plaintext_len) {
    if (plaintext_len) *plaintext_len = 0;
    if (!priv_key || !ciphertext || !enc_header || !expected_sha256 || !plaintext_len ||
        enc_header_len != 1137 || enc_header[0] != 2 || ciphertext_len < 52) return NULL;
    /* Count legacy payload bytes with bounds checks, without allocating. */
    size_t pos = 0, expected = 0;
    while (pos < ciphertext_len) {
        if (ciphertext_len - pos < 52) return NULL;
        uint32_t n = (uint32_t)ciphertext[pos] |
            ((uint32_t)ciphertext[pos + 1] << 8) |
            ((uint32_t)ciphertext[pos + 2] << 16) |
            ((uint32_t)ciphertext[pos + 3] << 24);
        if (n > ZUPT_ENCRYPT_BLOCK_SIZE || (size_t)n + 52 > ciphertext_len - pos ||
            n > SIZE_MAX - expected) return NULL;
        expected += n;
        pos += (size_t)n + 52;
    }
    zupt_keyring_t kr = {0};
    if (zupt_hybrid_decrypt_init_legacy_mem(&kr, priv_key, priv_key_len,
                                           enc_header, enc_header_len) != 0) {
        zupt_munlock_keys(&kr, sizeof(kr));
        return NULL;
    }
    size_t restored_len = 0;
    uint8_t *plaintext = decrypt_records(&kr, ciphertext, ciphertext_len,
                                        expected, &restored_len);
    zupt_munlock_keys(&kr, sizeof(kr));
    if (!plaintext) return NULL;
    uint8_t digest[32];
    zupt_sha256(plaintext, restored_len, digest);
    int valid = same_tag(digest, expected_sha256);
    zupt_secure_wipe(digest, sizeof(digest));
    if (!valid) { discard_plain(plaintext, restored_len); return NULL; }
    *plaintext_len = restored_len;
    return plaintext;
}
