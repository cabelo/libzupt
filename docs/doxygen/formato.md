/**
 * @page page-formato Formato em disco
 *
 * @brief Layout dos contêineres e dos envelopes criptografados.
 *
 * @details
 *
 * A biblioteca tem duas representações em disco distintas. A primeira é o
 * contêiner de arquivamento, descrito pelas estruturas empacotadas do cabeçalho
 * (`zupt_archive_header_t`, `zupt_footer_t`, `zupt_index_entry_t`). A segunda é o
 * envelope criptografado de chave híbrida, descrito em `docs/FORMAT.md` e
 * implementado em `src/zupt_crypto.c`. As duas não são a mesma coisa e este
 * documento descreve as duas, com as divergências marcadas.
 *
 * # Contêiner de arquivamento
 *
 * Sequência esperada, segundo os campos e os comentários de `include/zupt.h`:
 *
 * | Região | Conteúdo |
 * | --- | --- |
 * | Cabeçalho | 64 bytes: magic de 6 bytes (::ZUPT_MAGIC_0 a ::ZUPT_MAGIC_5), versão, flags globais, timestamp, ID de 16 bytes, deslocamento do cabeçalho de criptografia, deslocamento do comentário, 12 bytes reservados |
 * | Blocos de dados | Repetidos, cada um com magic de bloco (::ZUPT_BLOCK_MAGIC_0, ::ZUPT_BLOCK_MAGIC_1), tipo, codec, flags e payload |
 * | Cabeçalho de criptografia | Presente quando ::ZUPT_FLAG_ENCRYPTED está ligado; começa com o discriminador `0x03` |
 * | Índice | Bloco de índice (::ZUPT_BLOCK_INDEX) com as entradas `zupt_index_entry_t` |
 * | Rodapé | 32 bytes: deslocamento do índice, total de blocos, checksum, magic ASCII `ZEND`, versão |
 *
 * Todos os inteiros multibyte são little-endian. A conversão é feita pelos
 * helpers inline `zupt_le16_get/put`, `zupt_le32_get/put` e
 * `zupt_le64_get/put`.
 *
 * Tipos de bloco definidos: ::ZUPT_BLOCK_DATA (0x00), ::ZUPT_BLOCK_INDEX (0x02),
 * ::ZUPT_BLOCK_ENC_HEADER (0x03) e ::ZUPT_BLOCK_DEDUP_REF (0x04). Cada bloco de
 * dados é precedido pelos dois bytes de magic ::ZUPT_BLOCK_MAGIC_0 e
 * ::ZUPT_BLOCK_MAGIC_1.
 *
 * Codecs por bloco: ::ZUPT_CODEC_STORE (0x0000), ::ZUPT_CODEC_ZUPT_LZ (0x0008),
 * ::ZUPT_CODEC_ZUPT_LZH (0x0009), ::ZUPT_CODEC_ZUPT_LZHP (0x000A) e
 * ::ZUPT_CODEC_VAPTVUPT (0x0010). ::ZUPT_CODEC_AUTO (0xFFFF) pede
 * autodetecção, resolvida em `zupt_resolve_auto_codec()`.
 *
 * # Envelope criptografado
 *
 * É o que `docs/FORMAT.md` chama de "application format v2".
 *
 * \dotfile envelope.dot "Layout do envelope v2 tal como o código o escreve (src/zupt_cxx.c:351-398)"
 *
 * O desenho acima é a sequência que `zupt_hybrid_encrypt()` monta byte a byte.
 * Ele não contradiz as tabelas abaixo: os registros ali são os do lado C, de
 * `4 + n + 48` bytes (`u32le(n)` seguido de `nonce(16) ‖ cifra(n) ‖ HMAC(32)`),
 * e o aviso ao fim desta página registra que o emolduramento descrito em
 * `docs/FORMAT.md` é outro.
 *
 * ## Chave pública (1224 bytes)
 *
 * | Deslocamento | Campo | Tamanho |
 * | --- | --- | --- |
 * | 0 | ASCII `ZKEY` | 4 |
 * | 4 | Versão `0x02` | 1 |
 * | 5 | Flags `0x00` | 1 |
 * | 6 | Reservado, zero | 2 |
 * | 8 | Chave de encapsulação ML-KEM-768 (FIPS 203) | 1184 |
 * | 1192 | Chave pública X25519 | 32 |
 *
 * A chave privada repete os 1224 bytes iniciais com flags `0x01` e acrescenta
 * as chaves secretas, totalizando 3656 bytes. Nenhum dos dois formatos tem
 * checksum próprio: a integridade do envelope é o que é autenticada.
 *
 * ## Cabeçalho de cifra (1137 bytes)
 *
 * | Deslocamento | Campo | Tamanho |
 * | --- | --- | --- |
 * | 0 | Discriminador `0x03` | 1 |
 * | 1 | Texto cifrado ML-KEM-768 | 1088 |
 * | 1089 | Chave pública X25519 efêmera | 32 |
 * | 1121 | Nonce base por mensagem | 16 |
 *
 * ## Registros
 *
 * O texto plano é dividido em registros. Os oito primeiros bytes do nonce base
 * são combinados por XOR com o identificador do registro e os oito finais
 * funcionam como contador big-endian. O tamanho cifrado de um registro é
 * `12 + tamanho + 32`; uma mensagem vazia produz 96 bytes. A cifra é AES-256 e
 * o tag final tem 32 bytes.
 *
 * @warning `docs/FORMAT.md` descreve a API de C++ e das bindings. As funções C
 *          `zupt_encrypt_buffer()` e `zupt_decrypt_buffer()` usam o envelope
 *          `nonce(16) || cifra || HMAC(32)` descrito nas suas declarações, que
 *          não é o formato de registro com contador big-endian acima.
 *
 * @see \ref page-seguranca para a derivação de chaves.
 */
