/**
 * @page page-seguranca Notas de segurança
 *
 * @brief O que o desenho criptográfico protege, o que depende do chamador e as
 *         falhas observadas no código.
 *
 * @details
 *
 * # Construção implementada
 *
 * - Confidencialidade e integridade de blocos: AES-256-CTR com HMAC-SHA256 na
 *   ordem Encrypt-then-MAC. O MAC cobre `nonce || texto cifrado`, de modo que um
 *   bloco alterado ou com nonce trocado é rejeitado antes de o texto plano ser
 *   devolvido (`src/zupt_crypto.c`, `zupt_encrypt_buffer` e
 *   `zupt_decrypt_buffer`).
 * - Derivação de chave a partir de senha: PBKDF2-HMAC-SHA256 com
 *   `ZUPT_KDF_ITERATIONS` iterações sobre um salt de 32 bytes, produzindo 64
 *   bytes divididos em chave de cifra e chave de MAC.
 * - Modo híbrido pós-quântico: encapsulação ML-KEM-768 combinada com X25519; a
 *   chave de sessão sai de um KDF sobre os dois segredos compartilhados, o
 *   ciphertext e a chave pública efêmera (`hybrid_kdf()` em
 *   `src/zupt_crypto.c`).
 * - Aleatoriedade: `getrandom()` ou `/dev/urandom` em `zupt_random_bytes()`.
 *
 * # O que o chamador precisa garantir
 *
 * - Nunca reutilizar o par (keyring, `block_seq`). O nonce de bloco é o nonce
 *   base com os 8 bytes baixos XOR `block_seq`; repetir o par reaproveita a
 *   keystream e quebra a confidencialidade de ambos os blocos.
 * - Gerar salt e nonce frescos por arquivo com `zupt_random_bytes()`.
 * - Manter a chave privada protegida por permissão de arquivo e não a
 *   serializar para logs. `zupt_write_private_key()` abre o arquivo com
 *   `0600`, mas não faz `fsync()` e não protege a escrita no caminho `_WIN32`.
 *
 * # Falhas e lacunas observadas
 *
 * Os itens abaixo foram lidos do código durante a revisão da documentação. Eles
 * estão registrados aqui como resultado da leitura, não como correção aplicada.
 *
 * - `ZUPT_FLAG_CKSUM_XXH64` está definido como `(0u << 5)` em `include/zupt.h`,
 *   ou seja, não liga nenhum bit. Um arquivo que seleciona essa opção grava o
 *   mesmo valor de flag de um arquivo sem checksum.
 * - `zupt_aes256_ctx` guarda apenas as rodadas de cifra (`rk[60]`). Não existe
 *   agendamento para decifrar blocos AES no modo ECB/CBC; a decifração depende
 *   exclusivamente do modo CTR.
 * - A dispatch de AES-NI e AVX em `src/zupt_crypto.c` (sob `ZUPT_USE_JASMIN`)
 *   consulta `zupt_cpu` e `zupt_detect_cpu`, símbolos declarados em
 *   `include/zupt_cpuid.h` mas sem definição em `src/`. O comportamento
 *   depende, portanto, de uma definição externa à biblioteca.
 * - `include/zupt_keccak.h` não tem guarda `extern "C"`, o que quebra o link
 *   quando o cabeçalho é consumido de C++.
 * - `keccak_finalize()` em `src/zupt_keccak.c` faz `memset` com tamanho
 *   `rate - pt - 1`; quando `pt == rate` o tamanho pedido é `-1`.
 * - Chamar `keccak_finalize()` duas vezes no mesmo contexto produz saída
 *   errada sem qualquer sinal de erro.
 * - `zupt_legacy_mlkem768_decaps()` usa derivação de chave diferente do caminho
 *   FIPS, de modo que contêineres legados e contêineres novos não são
 *   intercambiáveis.
 * - `ZUPT_FLAG_DISK_IMAGE` é declarado, aparece em `zupt_disk_backup()` e nunca
 *   é consultado em nenhum `src/*.c`.
 *
 * # Camada de vínculos nativos
 *
 * Os exemplos com vínculos Node.js, Python e Java não adicionam lógica
 * criptográfica, mas movem dados sensíveis entre fronteiras de memória
 * gerida, e aí estão as lacunas mais relevantes desta camada.
 *
 * **Java (`examples_java/zupt_jni.cpp`)**
 *
 * - `Encryptor.java` é a única classe do pacote com métodos nativos que não
 *   chama `System.loadLibrary("Jzupt")`; usando apenas ela, `JNI_OnLoad` não
 *   roda e a primeira chamada falha com `UnsatisfiedLinkError`.
 * - `Java_com_libzupt_Encryptor_nativeEncryptMemorySecure` e
 *   `Java_com_libzupt_Decryptor_decryptMemorySecure` estão implementadas, mas
 *   não aparecem nas tabelas `encryptorMethods`/`decryptorMethods` nem como
 *   `native` nos arquivos Java correspondentes: código inalcançável.
 * - Os métodos "seguros" de `Encryptor.java` e `Decryptor.java` chamam
 *   `buffer.toBytes()`, que devolve uma cópia comum; o `zupt::SecureBuffer`
 *   não chega à chamada nativa, então a proteção dele se perde na fronteira.
 * - Não existe nenhuma chamada a `zupt::secureWipe()` em todo o caminho JNI:
 *   a chave privada chega como cópias `byte[]` em claro que nunca são
 *   zeradas, e os vetores locais que a contêm idem.
 * - Não há `JNI_OnUnload`, de modo que as referências globais
 *   `zuptErrorClass` e `keyPairClass` nunca são liberadas.
 * - `JNI_OnLoad` conta os elementos das tabelas de métodos com literais, e não
 *   com `sizeof`: um método acrescentado à tabela sem atualizar o literal
 *   fica sem vínculo, silenciosamente. Se `FindClass` falha, o bloco inteiro é
 *   ignorado e a função ainda devolve `JNI_VERSION_1_8`.
 *
 * **Python (`examples_python/zupt_pybind.cpp`)**
 *
 * - `py::register_exception<zupt::ZuptError>` não transporta `code()`: ao
 *   Python chega apenas a mensagem, e o código de erro da biblioteca se perde.
 * - `encrypt_memory`, `decrypt_memory` e `secure_wipe` aceitam qualquer
 *   inteiro como endereço. `encrypt_memory(0, 16)` termina em `SIGSEGV` dentro
 *   do processo, e `secure_wipe` escreve em qualquer endereço, inclusive
 *   memória do interpretador.
 * - `private_key` é exposto com `def_readonly`, o que impede reatribuir o
 *   atributo, mas não impede ler ou alterar o conteúdo: a chave privada fica
 *   viva em claro no heap do processo.
 * - `generate_keypair` não limpa o `zupt::KeyPair` local, ao contrário do
 *   vínculo Node.js.
 *
 * **Node.js (`examples_nodejs/src/zupt_napi.cpp`)**
 *
 * - Os construtores de `Encryptor` e `Decryptor` pegam `info[0]` sem verificar
 *   `IsBuffer()`; um argumento de tipo errado aborta o processo em vez de
 *   levantar `TypeError`.
 * - `randomBytes` usa `Uint32Value()`, que aceita números negativos:
 *   `randomBytes(-1)` vira tentativa de alocação de 4 GiB.
 * - `LoadKeyPair` não aplica `secureWipe` ao objeto lido, enquanto
 *   `GenerateKeyPair` aplica.
 * - Em nenhum dos três vínculos a chave privada é removida do lado gerido
 *   (JavaScript, Python, JVM): a limpeza só acontece na cópia nativa, e mesmo
 *   assim apenas em alguns caminhos.
 *
 * @see \ref page-limitacoes, \ref page-memoria e \ref page-formato.
 */
