/*
 * libzupt - C++ wrapper for hybrid post-quantum encryption
 * C API for C++ implementation
 *
 * SPDX-License-Identifier: MIT
 */

/**
 * @file  zupt_cxx.h
 * @brief ABI C do núcleo de criptografia híbrida pós-quântica da libzupt.
 * @details Superfície de ABI C consumida pela camada C++ (include/zupt.hpp e
 * src/zupt_crypto.cpp) e pelos bindings de outras linguagens. As implementações
 * ficam em src/zupt_cxx.c, que monta o formato de chave "ZKEY" e o envelope
 * "ZUP2" usando as primitivas de src/zupt_mlkem.c, src/zupt_x25519.c e
 * src/zupt_crypto.c.
 *
 * Propriedade de memória: as funções que devolvem uint8_t* alocados
 * (zupt_read_file, zupt_hybrid_encrypt, zupt_hybrid_decrypt e
 * zupt_hybrid_decrypt_legacy) entregam buffers obtidos com malloc dentro desta
 * biblioteca. A partir do retorno o chamador é o dono do buffer e deve libera-
 * lo com zupt_free(), nunca com free() do CRT da aplicação: em Windows a
 * biblioteca e o chamador podem estar ligados a CRTs distintos, e alocação e
 * liberação precisam ocorrer no mesmo heap; o mesmo requisito vale para
 * fronteiras de FFI (Python, Go, Rust, Java, Node.js, .NET, PHP). Os buffers de
 * entrada permanecem de propriedade do chamador, que os aloca e os libera.
 *
 * Versionamento: ZUPT_KEY_FORMAT_VERSION e ZUPT_ENVELOPE_FORMAT são números de
 * emolduramento da aplicação e não descrevem o conjunto de parâmetros do ML-KEM
 * (1184/2400/1088), definidos em include/zupt_mlkem.h.
 */

#ifndef ZUPT_CXX_H
#define ZUPT_CXX_H

#include <stdint.h>
#include <stddef.h>

/* Application framing versions, distinct from the ML-KEM parameter set. */

/**
 * @def ZUPT_KEY_FORMAT_VERSION
 * @brief Número de formato do cabeçalho de chave "ZKEY" gerado por esta versão.
 * @details É o valor gravado no byte de offset 4 do layout "ZKEY" (ver
 * zupt_hybrid_keygen_c). A leitura aceita este valor e também o valor 1
 * (formato legado) em zupt_hybrid_export_pubkey_c, zupt_write_private_key,
 * KeyGenerator::loadKeyPair e KeyGenerator::loadPublicKey. A cifra não aceita
 * o valor 1: parse_pubkey_buf, em src/zupt_crypto.c, exige exatamente este
 * valor, de modo que uma chave pública derivada de um material legado v1 é
 * rejeitada por Encryptor.
 * @see ZUPT_ENVELOPE_FORMAT, zupt_hybrid_decrypt_legacy
 */
#define ZUPT_KEY_FORMAT_VERSION 2

/**
 * @def ZUPT_ENVELOPE_FORMAT
 * @brief Discriminador de envelope v2 esperado no byte de offset 0 do
 *        cabeçalho de cifra (1137 bytes).
 * @details Gravado em enc_header[0] pela camada de cifra (src/zupt_crypto.c) e
 * verificado por zupt_hybrid_decrypt. O valor 2 corresponde ao discriminador
 * do formato legado v1, aceito apenas por zupt_hybrid_decrypt_legacy. Não há
 * fallback automático entre os dois caminhos.
 * @see zupt_hybrid_encrypt, zupt_hybrid_decrypt, zupt_hybrid_decrypt_legacy
 */
#define ZUPT_ENVELOPE_FORMAT 3

/**
 * @def ZUPT_API
 * @brief Macro de visibilidade/exportação aplicada a toda a superfície C desta
 *        ABI.
 * @details A definição depende da plataforma e do modo de vinculação:
 * - Windows ou Cygwin, com ZUPT_STATIC definido: macro vazia (vinculação
 *   estática, sem exportação).
 * - Windows ou Cygwin, com ZUPT_EXPORTS definido: dllexport, usado ao compilar
 *   a DLL.
 * - Windows ou Cygwin sem nenhuma das duas: dllimport, usado pelo consumidor.
 * - Demais plataformas com GCC 4 ou superior: visibilidade default, ou seja,
 *   o símbolo fica exposto mesmo quando a compilação usa
 *   -fvisibility=hidden.
 * - Demais plataformas com compilador anterior: macro vazia.
 * @note A camada C++ (src/zupt_crypto.cpp) aplica ZUPT_API a secureWipe, que é
 * um símbolo C++ exportado dentro do namespace zupt.
 */
#if defined(_WIN32) || defined(__CYGWIN__)
  #ifdef ZUPT_STATIC
    #define ZUPT_API
  #elif defined(ZUPT_EXPORTS)
    #define ZUPT_API __declspec(dllexport)
  #else
    #define ZUPT_API __declspec(dllimport)
  #endif
#else
  #if defined(__GNUC__) && __GNUC__ >= 4
    #define ZUPT_API __attribute__((visibility("default")))
  #else
    #define ZUPT_API
  #endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Libera um buffer devolvido por uma função desta ABI C.
 * @details Envolve free() do CRT com o qual a própria biblioteca foi
 * compilada. É a única forma correta de liberar os buffers retornados por
 * zupt_read_file, zupt_hybrid_encrypt, zupt_hybrid_decrypt e
 * zupt_hybrid_decrypt_legacy, e é obrigatório quando o chamador vive em outro
 * binário (DLL Windows vinculada a um CRT diferente da aplicação, ou qualquer
 * binding por FFI), pois alocação e liberação têm de cair no mesmo heap.
 * Não zera o conteúdo: para material sensível, limpe o buffer antes
 * (zupt::secureWipe na camada C++, zupt_secure_wipe em C).
 * @param[in] ptr Buffer devolvido por esta ABI, ou NULL.
 * @note free(NULL) é inócuo, portanto chamar esta função com NULL é seguro.
 * @see zupt_read_file, zupt_hybrid_encrypt, zupt_hybrid_decrypt,
 * zupt_hybrid_decrypt_legacy
 */
ZUPT_API void zupt_free(void* ptr);

/* KEY GENERATION C API */

/**
 * @brief Gera um par de chaves híbrido ML-KEM-768 + X25519 e o serializa no
 *        layout "ZKEY".
 * @details Executa zupt_mlkem768_keygen, obtém 32 bytes aleatórios com
 * zupt_random_bytes e deriva a chave pública X25519 com zupt_x25519_base
 * (clamping RFC 7748 aplicado dentro de zupt_x25519). Serializa os dois pares
 * no formato observável "ZKEY":
 * @verbatim
 * chave pública (1224 bytes):
 *   0    4  "ZKEY"
 *   4    1  versão = ZUPT_KEY_FORMAT_VERSION
 *   5    1  0x00 (não contém chave privada)
 *   6    2  reservados, zero
 *   8    1184 chave de encapsulação ML-KEM-768
 *   1192 32   chave pública X25519
 *
 * chave privada (3656 bytes):
 *   0    4  "ZKEY"
 *   4    1  versão = ZUPT_KEY_FORMAT_VERSION
 *   5    1  0x01 (contém chave privada)
 *   6    2  reservados, zero
 *   8    1184 chave ML-KEM-768 pública (repetida)
 *   1192 32   chave pública X25519 (repetida)
 *   1224 2400 chave de decapsulação ML-KEM-768
 *   3624 32   chave privada X25519
 * @endverbatim
 * Os buffers temporários das chaves secretas (ml_sk, x_sk) são limpos com
 * zupt_secure_wipe antes do retorno; as cópias escritas nos buffers de saída
 * passam a ser do chamador. Não há checksum no final do registro.
 * @param[out] pub_key  Capacidade obrigatória: 1224 bytes.
 * @param[out] priv_key Capacidade obrigatória: 3656 bytes.
 * @retval 0  Sucesso.
 * @retval -1 pub_key ou priv_key é NULL, ou zupt_mlkem768_keygen falhou.
 * @warning A assinatura não transporta tamanhos: a capacidade exigida é
 * implícita e não verificada; passar buffers menores é comportamento
 * indefinido.
 * @see ZUPT_KEY_FORMAT_VERSION, zupt_hybrid_export_pubkey_c
 */
ZUPT_API int zupt_hybrid_keygen_c(uint8_t* pub_key, uint8_t* priv_key);

/**
 * @brief Deriva a chave pública "ZKEY" a partir de uma chave privada "ZKEY".
 * @details Valida a moldura da chave privada: assinatura "ZKEY", byte de versão
 * igual a 1 ou a ZUPT_KEY_FORMAT_VERSION, byte 5 igual a 1 (chave privada
 * presente) e bytes 6 e 7 iguais a zero. Copia os 1184 bytes de ml_pk e os 32
 * bytes de x_pk para o destino, grava a assinatura, preserva o byte de versão
 * lido da origem e zera o byte 5 (flag "sem chave privada"). Não verifica o
 * conteúdo das chaves (não invoca zupt_mlkem768_public_key_check) e não confere
 * o tamanho real do buffer de origem, apenas os bytes de cabeçalho.
 * @param[in]  priv_key Chave privada serializada: 3656 bytes no layout "ZKEY".
 * @param[out] pub_key  Capacidade obrigatória: 1224 bytes.
 * @retval 0  Sucesso.
 * @retval -1 ponteiro nulo, assinatura inválida, versão não aceita, byte 5
 *         diferente de 1 ou bytes reservados não nulos.
 * @note O byte de versão é copiado da origem: uma chave privada de versão 1
 * gera uma chave pública de versão 1, que Encryptor e parse_pubkey_buf
 * (src/zupt_crypto.c) rejeitam, pois exigem ZUPT_KEY_FORMAT_VERSION.
 * @see zupt_hybrid_keygen_c
 */
ZUPT_API int zupt_hybrid_export_pubkey_c(const uint8_t* priv_key, uint8_t* pub_key);

/* FILE I/O C API */

/* Read entire file into buffer
 * Returns allocated buffer (caller must free), or NULL on error
 * size: output parameter for file size
 */
/**
 * Lê um arquivo inteiro para um buffer recém-alocado.
 *
 * Implementação POSIX/ANSI: `fopen(path, "rb")`, `fseek(SEEK_END)`, `ftell`,
 * `fseek(SEEK_SET)` e um único `fread`. Symlinks e outros nomes indiretos são
 * seguidos (não há `O_NOFOLLOW` aqui).
 * @param path Caminho do arquivo. `NULL` é rejeitado.
 * @param size Saída: número de bytes lidos. **Obrigatória**: `NULL` faz a
 *             função devolver `NULL` sem tocar no disco.
 * @return Buffer alocado com `malloc` de `*size` bytes (ou 1 byte quando o
 *         arquivo está vazio), sem terminador NUL. Deve ser liberado com
 *         `zupt_free()`. Conteúdo vazio devolve buffer não inicializado de
 *         1 byte com `*size == 0`.
 * @retval NULL em qualquer falha: caminho `NULL`, `size` `NULL`, arquivo
 *         inexistente ou não abertável, `fseek`/`ftell` malsucedidos,
 *         `malloc` falho ou `fread` lendo menos de `*size` bytes. Os códigos
 *         de erro internos não são diferenciados, e `errno` pode ser
 *         sobrescrito pelas chamadas de `stdio` anteriores.
 */
ZUPT_API uint8_t* zupt_read_file(const char* path, size_t* size);

/* Write buffer to file
 * Returns 0 on success, -1 on error
 */
/**
 * Escreve um buffer em arquivo, substituindo o conteúdo existente.
 *
 * Caminho simples de `stdio`: `fopen(path, "wb")` + `fwrite` + `fclose`. O
 * arquivo é criado com permissões `0666 & ~umask` e symlinks são seguidos.
 * Não há `fsync` nem verificação de proprietário/tipo de arquivo — para
 * material sensível use `zupt_write_private_key()`.
 * @param path Caminho do arquivo. `NULL` é rejeitado.
 * @param data Conteúdo a escrever. Pode ser `NULL` apenas quando `size == 0`.
 * @param size Número de bytes a escrever.
 * @return `0` quando todos os bytes foram escritos e `fclose` teve sucesso.
 * @retval -1 em qualquer falha: parâmetros inválidos, `fopen` malsucedido,
 *           escrita parcial (inclusive em `fclose` de um `FILE` com erro
 *           pendente). O arquivo pode ficar truncado/parcialmente escrito.
 */
ZUPT_API int zupt_write_file(const char* path, const uint8_t* data, size_t size);

/* API-format private keys only. POSIX: checked owner, regular single-link file,
 * O_NOFOLLOW, mode 0600 before writing. Windows: caller controls directory ACLs. */
/**
 * Persiste um arquivo de chave privada privada-híbrida (formato `ZKEY`) com
 * verificações de segurança no POSIX.
 *
 * Valida o conteúdo antes de tocar no disco: tamanho **exatamente**
 * `3656` bytes, mágica `ZKEY`, byte de versão `1` ou `ZUPT_KEY_FORMAT_VERSION`
 * (2), byte de flags `0x01` (chave privada presente) e os dois bytes
 * reservados (`[6]`, `[7]`) zerados. Ou seja, chaves públicas não são aceitas.
 *
 * No POSIX: `open(path, O_WRONLY | O_CREAT | O_NOFOLLOW | O_NONBLOCK, 0600)`;
 * em seguida `fstat` exige arquivo regular, `st_nlink == 1`, `st_uid ==
 * geteuid()`, e aplica `fchmod(0600)` e `ftruncate(0)` antes de escrever. As
 * verificações acontecem **depois** do `open`, mas **antes** do truncamento,
 * de modo que um arquivo pertencente a outro usuário não é sobrescrito. No
 * Windows, a função cai em `zupt_write_file()` — sem endurecimento; as
 * permissões ficam sob controle do chamador/ACL do diretório.
 * @param path Caminho do arquivo. `NULL` é rejeitado.
 * @param data Buffer de 3656 bytes contendo a chave privada serializada.
 * @param size Tamanho de `data`: deve ser `3656`, senão a função rejeita.
 * @return `0` quando o arquivo foi escrito por completo e `fclose` teve
 *         sucesso.
 * @retval -1 em qualquer falha: validação de conteúdo, `open` malsucedido
 *           (inclusive rejeição de symlink por `O_NOFOLLOW`), `fstat` falho,
 *           arquivo não regular, `nlink != 1`, dono diferente do usuário
 *           efetivo, `fchmod`/`ftruncate`/`fdopen` falhos ou escrita parcial.
 *           Não há como distinguir as causas pelo valor de retorno.
 * @note Não chama `fsync`: após o retorno bem-sucedido os dados estão no
 *       cache do kernel, não necessariamente no meio físico.
 */
ZUPT_API int zupt_write_private_key(const char* path, const uint8_t* data, size_t size);

/* ENCRYPTION/DECRYPTION C API */

/* Encrypt buffer with hybrid encryption
 * pub_key: public key buffer
 * pub_key_len: public key size
 * plaintext: input data
 * plaintext_len: input size
 * enc_header: output encryption header
 * enc_header_len: output header size
 * Returns allocated ciphertext (caller must free), or NULL on error
 * ciphertext_len: output ciphertext size
 */
/**
 * Cifra um buffer com a cifra híbrida pós-quântica (ML-KEM-768 + X25519) e
 * produz um envelope v2 (`ZUP2`).
 *
 * Layout devolvido (documentado em `docs/FORMAT.md`):
 * `"ZUP2"` (4) ‖ `u64le(plaintext_len)` (8) ‖ registros ‖ tag final (32), onde
 * cada registro é `u32le(tamanho)` (4) ‖ envelope de 48+`n` bytes
 * (nonce 16 ‖ AES-256-CTR ‖ MAC 32). O total é
 * `12 + plaintext_len + blocos*52 + 32`, com **pelo menos um bloco** mesmo
 * para entrada vazia (`96` bytes). O bloco tem no máximo
 * `ZUPT_ENCRYPT_BLOCK_SIZE` = 4 MiB.
 *
 * A tag final é um HMAC derivado de chave própria que cobre o cabeçalho de
 * cifra completo (1137 bytes) e todos os registros.
 * @param[in] pub_key Chave pública serializada (`ZKEY`), de `pub_key_len`
 *                    bytes. Validada pelo lado C; `NULL` é rejeitado.
 * @param[in] pub_key_len Tamanho de `pub_key`.
 * @param[in] plaintext Texto em claro. `NULL` só é aceito quando
 *                      `plaintext_len == 0`.
 * @param[in] plaintext_len Tamanho do texto em claro.
 * @param[out] enc_header Buffer **do chamador** que recebe o cabeçalho de
 *                        cifra; deve ter capacidade para pelo menos 1137
 *                        bytes. Esta função não informa nem limita a
 *                        capacidade — o lado C escreve os 1137 bytes.
 * @param[out] enc_header_len Recebe o tamanho efetivo do cabeçalho
 *                            (1137). É zerada na entrada e em falhas.
 * @param[out] ciphertext_len Recebe o tamanho total do envelope devolvido. É
 *                             zerada na entrada e em falhas.
 * @return Envelope completo, `malloc`'d, de `*ciphertext_len` bytes; o
 *         chamador é dono e deve liberar com `zupt_free()`.
 * @retval NULL parâmetros nulos, capacidade de estouro aritmética, `malloc`
 *              falho, rejeição da chave pública ou falha do lado C. Todas as
 *              causas são indistinguíveis pelo valor de retorno.
 * @note O cabeçalho de cifra contém o ciphertext da encapsulação ML-KEM e o
 *       epônimo X25519: é material público, mas necessário para decifrar.
 * @see zupt_hybrid_decrypt, zupt_hybrid_encrypt_init_mem
 */
ZUPT_API uint8_t* zupt_hybrid_encrypt(const uint8_t* pub_key, size_t pub_key_len,
                                      const uint8_t* plaintext, size_t plaintext_len,
                                      uint8_t* enc_header, size_t* enc_header_len,
                                      size_t* ciphertext_len);

/* Decrypt buffer with hybrid encryption
 * priv_key: private key buffer
 * priv_key_len: private key size
 * ciphertext: input ciphertext
 * ciphertext_len: input ciphertext size
 * enc_header: encryption header from encryption
 * enc_header_len: header size
 * Returns allocated plaintext (caller must free), or NULL on error
 * plaintext_len: output plaintext size
 */
/**
 * Decifra um envelope v2 (`ZUP2`) produzido por `zupt_hybrid_encrypt()`.
 *
 * Ordem de execução do código (autenticar antes de decifrar):
 *   1. Valida ponteiros, `enc_header_len == 1137`, o primeiro byte do
 *      cabeçalho (`ZUPT_ENVELOPE_FORMAT`) e a mágica `ZUP2`, e exige
 *      `ciphertext_len >= 96`.
 *   2. Deriva o keyring a partir da chave privada e do cabeçalho de cifra.
 *   3. Recomputa a tag final sobre cabeçalho + registros e compara em tempo
 *      constante. Somente se a tag conferir é que os tamanhos dos registros
 *      são interpretados e o texto em claro é decifrado.
 * @param[in] priv_key Chave privada serializada (`ZKEY`, 3656 bytes).
 * @param[in] priv_key_len Tamanho de `priv_key`.
 * @param[in] ciphertext Envelope completo produzido pela cifra híbrida.
 * @param[in] ciphertext_len Tamanho do envelope.
 * @param[in] enc_header Cabeçalho de cifra devolvido pela cifra (1137 bytes).
 * @param[in] enc_header_len Deve ser exatamente 1137.
 * @param[out] plaintext_len Recebe o tamanho do texto em claro. É zerada na
 *                            entrada e em todas as falhas.
 * @return Texto em claro `malloc`'d de `*plaintext_len` bytes, de propriedade
 *         do chamador (liberar com `zupt_free()`).
 * @retval NULL parâmetros nulos, cabeçalho inválido, envelope curto, chave
 *              rejeitada, tag final que não confere, registros inconsistentes
 *              (tamanhos fora do esperado, `total != esperado`) ou `malloc`
 *              falho. Falha de autenticação não é distinguível de erro
 *              estrutural pelo valor de retorno.
 * @note Os buffers temporários de texto em claro são zerados com
 *       `zupt_secure_wipe()` antes de `free()` nos caminhos de falha.
 * @see zupt_hybrid_encrypt, zupt_hybrid_decrypt_init_mem
 */
ZUPT_API uint8_t* zupt_hybrid_decrypt(const uint8_t* priv_key, size_t priv_key_len,
                                      const uint8_t* ciphertext, size_t ciphertext_len,
                                      const uint8_t* enc_header, size_t enc_header_len,
                                      size_t* plaintext_len);

/* Explicit v1 recovery only. expected_sha256 must come from a trusted source:
 * the legacy format cannot authenticate removal of complete final blocks.
 * New keys/envelopes are never interpreted as legacy. Returns NULL on error. */
/**
 * Decifra explicitamente um envelope do formato legado **v1**, usando a chave
 * privada e um SHA-256 de confiança do chamador.
 *
 * Diferenças em relação a `zupt_hybrid_decrypt()`:
 *   - não existe mágica de envelope nem tag final: o pacote é apenas a
 *     sequência de registros `u32le(tamanho)` ‖ envelope de 48+`n` bytes;
 *   - o cabeçalho de cifra deve ter `enc_header[0] == 2` (valor literal no
 *     código, igual a `ZUPT_KEY_FORMAT_VERSION`), e o keyring é derivado por
 *     `zupt_hybrid_decrypt_init_legacy_mem()`, o KDF legado;
 *   - a integridade vem **de fora**: o código calcula `SHA-256(plaintext)` e
 *     compara, em tempo constante, com `expected_sha256`. Sem esse valor não
 *     há como detectar substituição de conteúdo, e o próprio formato legado
 *     não autentica a remoção de blocos finais.
 * @param[in] priv_key Chave privada serializada (`ZKEY`).
 * @param[in] priv_key_len Tamanho de `priv_key`.
 * @param[in] ciphertext Pacote legado (sem prefixo `ZUP2` e sem tag).
 * @param[in] ciphertext_len Tamanho do pacote.
 * @param[in] enc_header Cabeçalho de cifra legado (1137 bytes).
 * @param[in] enc_header_len Deve ser exatamente 1137.
 * @param[in] expected_sha256 Digest SHA-256 (32 bytes) do texto em claro
 *                          esperado, obtido de fonte confiável. Obrigatório.
 * @param[out] plaintext_len Recebe o tamanho recuperado. É zerada na entrada e
 *                            em todas as falhas.
 * @return Texto em claro `malloc`'d, de propriedade do chamador (liberar com
 *         `zupt_free()`).
 * @retval NULL parâmetros nulos, cabeçalho inválido, pacote mais curto que um
 *              registro, contagem de registros fora dos limites, chave
 *              rejeitada pelo KDF legado, `malloc` falho, registro
 *              inconsistente, ou SHA-256 do texto recuperado diferente de
 *              `expected_sha256`.
 * @note Novos pares de chaves e envelopes nunca são interpretados como
 *       legado: esta é a única porta de entrada para o formato antigo.
 * @see zupt_hybrid_decrypt, ZUPT_KEY_FORMAT_VERSION
 */
ZUPT_API uint8_t* zupt_hybrid_decrypt_legacy(
    const uint8_t* priv_key, size_t priv_key_len,
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* enc_header, size_t enc_header_len,
    const uint8_t expected_sha256[32], size_t* plaintext_len);

#ifdef __cplusplus
}
#endif

#endif /* ZUPT_CXX_H */
