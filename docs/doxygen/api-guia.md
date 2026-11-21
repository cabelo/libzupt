/**
 * @page page-api-guia Guia da API pública
 *
 * Convenções, tipos e a ordem correta de chamadas. `include/zupt.h` é a
 * frente C pública, `include/zupt.hpp` a frente C++ e `include/zupt_cxx.h`
 * a frente compartilhada com os vínculos nativos (Java e Node.js).
 *
 * @see @ref page-inventario, lista completa de arquivos e símbolos.
 * @see @ref page-erros, o enumerado de códigos e onde ele é usado.
 *
 * # Cinco formatos de retorno
 *
 * - Código de erro enumerado. As operações de arquivamento devolvem
 *   ::zupt_error_t, com @ref ZUPT_OK (0) em sucesso:
 *   @ref zupt_compress_solid, @ref zupt_compress_files,
 *   @ref zupt_extract_archive, @ref zupt_list_archive,
 *   @ref zupt_test_archive, @ref zupt_disk_backup e
 *   @ref zupt_disk_restore.
 * - `int` com `0` em sucesso e negativo em erro. Exemplos:
 *   @ref zupt_hybrid_keygen, @ref zupt_hybrid_export_pubkey,
 *   @ref zupt_hybrid_encrypt_init, @ref zupt_hybrid_decrypt_init,
 *   @ref zupt_hybrid_encrypt_init_mem, @ref zupt_hybrid_decrypt_init_mem,
 *   @ref zupt_mlock_keys, @ref zupt_detect_filetype,
 *   @ref zupt_write_varint, @ref zupt_read_varint.
 * - Contagem de bytes em `size_t`, com `0` em falha: @ref zupt_lz_compress,
 *   @ref zupt_lzh_compress, @ref zupt_lz_decompress,
 *   @ref zupt_lzh_decompress e as funções de limite
 *   @ref zupt_lz_bound, @ref zupt_lzh_bound.
 * - Ponteiro recém-alocado, com `NULL` como único sinal de falha:
 *   @ref zupt_encrypt_buffer, @ref zupt_decrypt_buffer e, em
 *   `include/zupt_cxx.h`, @ref zupt_hybrid_encrypt,
 *   @ref zupt_hybrid_decrypt e @ref zupt_hybrid_decrypt_legacy.
 * - Sem valor de retorno (`void`): as primitivas (@ref zupt_sha256,
 *   @ref zupt_aes256_ctr, @ref zupt_hmac_sha256, @ref zupt_pbkdf2_sha256,
 *   @ref zupt_secure_wipe, @ref zupt_derive_keys, @ref zupt_sha3_256,
 *   @ref zupt_shake128), @ref zupt_munlock_keys e @ref zupt_random_bytes.
 *
 * `zupt_random_bytes` é a única função `void` que pode encerrar o processo:
 * se o sistema entrega menos bytes que o pedido, ela chama `exit(1)`.
 *
 * # Buffers de saída e propriedade de memória
 *
 * @ref zupt_encrypt_buffer e @ref zupt_decrypt_buffer alocam o resultado e
 * escrevem o tamanho em `size_t *olen`. Em @ref zupt_decrypt_buffer o
 * retorno `NULL` agrupa causas distintas — MAC inválido, nonce divergente,
 * comprimento inconsistente e falha de alocação — sem nenhuma forma de
 * distingui-las por esta interface.
 *
 * As funções de compressão recebem o buffer e a capacidade do chamador:
 * @ref zupt_lz_compress recebe `dst` e `dcap` e devolve quantos bytes
 * escreveu. Reserve `zupt_lz_bound(slen)` bytes para não perder o resultado.
 *
 * O que a biblioteca aloca passa a ser do chamador, que libera com `free()`.
 * Material sensível deve ser limpo com @ref zupt_secure_wipe antes de
 * liberar.
 *
 * # Cifrar dados em memória
 *
 * A senha, o salt e o nonce base viram chaves por @ref zupt_derive_keys,
 * que preenche os campos de ::zupt_keyring_t com PBKDF2-HMAC-SHA256. A
 * senha é medida com `strlen`, então um `'\0'` embutido corta a entrada sem
 * nenhum aviso.
 *
 * @code
 * zupt_keyring_t kr;
 * uint8_t salt[ZUPT_SALT_SIZE], nonce[ZUPT_NONCE_SIZE];
 *
 * memset(&kr, 0, sizeof kr);
 * zupt_random_bytes(salt, sizeof salt);
 * zupt_random_bytes(nonce, sizeof nonce);
 * zupt_derive_keys(&kr, senha, salt, nonce, ZUPT_KDF_ITERATIONS);
 * @endcode
 *
 * A partir daí @ref zupt_encrypt_buffer produz um envelope
 * Encrypt-then-MAC, `[16 bytes de nonce][plen cifrado][32 bytes de
 * HMAC-SHA256]`, e escreve `16 + plen + 32` em `*olen`:
 *
 * @code
 * uint64_t seq = 0;
 * size_t olen = 0;
 * uint8_t *env = zupt_encrypt_buffer(&kr, plain, plen, seq, &olen);
 * if (env) {
 *   // usa env[0..olen-1]
 *   free(env);
 * }
 * @endcode
 *
 * O par (chave, `seq`) não pode se repetir: o nonce do bloco é o
 * `base_nonce` do anel com os 8 bytes menos significativos XOR `seq`, e a
 * keystream seria reaproveitada.
 *
 * @ref zupt_encrypt_buffer, declarada em `include/zupt.h:1019`, não tem
 * definição nesta árvore; a descrição acima é o contrato da interface, não
 * comportamento observável do `libzupt` compilado aqui. Os vínculos
 * nativos implementam um envelope próprio, descrito em @ref page-formato.
 *
 * # Decifrar um envelope em memória
 *
 * A sequência e o salt não estão dentro do envelope: vêm de fora e precisam
 * ser os mesmos da cifra.
 *
 * @code
 * size_t plen = 0;
 * uint8_t *plain = zupt_decrypt_buffer(&kr, env, olen, seq, &plen);
 * if (plain) {
 *   // plain[0..plen-1]
 *   zupt_secure_wipe(plain, plen);
 *   free(plain);
 * }
 * @endcode
 *
 * O HMAC é recomputado e conferido antes de qualquer cópia; o nonce do
 * envelope é comparado com o esperado para `seq`.
 *
 * # API C++
 *
 * `include/zupt.hpp`, namespace `zupt`:
 *
 * - ::zupt::SecureBuffer — buffer de tamanho fixo, não copiável, com
 *   `zeroize()`.
 * - ::zupt::KeyGenerator — `generateKeyPair()`, `loadKeyPair()`,
 *   `loadPublicKey()`, `exportPublicKey()`, `saveKeyPair()`.
 * - ::zupt::Encryptor — construído com a chave pública; `encryptFile()` e
 *   as três sobrecargas de `encryptMemory()` devolvem um
 *   `std::pair<std::vector<uint8_t>, std::vector<uint8_t>>` de
 *   `[texto cifrado][cabeçalho de cifra]`. O tamanho do cabeçalho vem de
 *   `Encryptor::getEncryptionHeaderSize()`, um `static constexpr`.
 * - ::zupt::Decryptor — construído com a chave privada; `decryptFile()`,
 *   `decryptMemory()` e `decryptMemorySecure()` pedem o cabeçalho de cifra
 *   como argumento separado.
 * - Funções soltas: @ref zupt::randomBytes, @ref zupt::sha256 (duas
 *   sobrecargas), @ref zupt::sha3_512, @ref zupt::secureWipe,
 *   @ref zupt::getVersion e @ref zupt::getLibraryName.
 * - ::zupt::ZuptError, exceção derivada de `std::runtime_error` que carrega
 *   um código do `enum class zupt::ErrorCode` (`OK = 0`, `ERR_IO = -1`,
 *   `ERR_CORRUPT = -2`, `ERR_BAD_MAGIC = -3` e assim por diante).
 *
 * @see @ref page-concorrencia antes de compartilhar uma instância entre
 *      threads.
 * @see @ref page-limitacoes — a versão devolvida por @ref zupt::getVersion
 *      não coincide com a que o cabeçalho C proclama.
 */
