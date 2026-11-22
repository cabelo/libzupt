/*
 * Zupt — Backup-oriented compression with AES-256 encryption
 * Copyright (c) 2026 Cristian Cezar Moisés
 * SPDX-License-Identifier: MIT
 */
/**
 * @cond PORT
 * @file   zupt.h
 * @brief  Cabeçalho público da libzupt: constantes de formato, primitivas criptográficas e API de arquivamento.
 * @details Este é o guarda-chuva de inclusão da biblioteca. Ele declara:
 * - macros de formato (magic, versões de formato, limites, flags
 * globais, tipos de cifra, tipos de bloco, identificadores de codec);
 * - as estruturas do formato em disco (`zupt_archive_header_t`,
 * `zupt_footer_t`), empacotadas byte a byte e serializadas em
 * little-endian;
 * - as estruturas em memória (`zupt_index_entry_t`, `zupt_block_t`,
 * `zupt_keyring_t`, `zupt_filelist_t`, `zupt_options_t`);
 * - auxiliares `static inline`: serialização little-endian, limpeza
 * segura de memória e teste de arquivo regular;
 * - as primitivas criptográficas implementadas nesta árvore
 * (SHA-256, AES-256, HMAC-SHA256, PBKDF2, AES-256-CTR, derivação de
 * chaves, envelope Encrypt-then-MAC, XXH64, aleatoriedade,
 * locking de memória);
 * - a API de arquivamento, compressão, extração, deduplicação e
 * imagem de disco.
 *
 * Endianidade: os campos numéricos multibyte do formato em disco são
 * little-endian. Os helpers `zupt_le*_put`/`zupt_le*_get` fazem a
 * conversão byte a byte, então o resultado não depende da endianidade
 * do host. Os tipos `zupt_archive_header_t` e `zupt_footer_t` usam
 * o pragma `pack(push,1)`: gravá-los como um bloco único de bytes só
 * produz little-endian em host little-endian, motivo pelo qual a
 * serialização usa os helpers acima em vez de escrita direta dos
 * structs.
 *
 * Convenção de retorno: a maior parte da API devolve `zupt_error_t`
 * (0 = sucesso, negativos = erro). As funções do grupo de cifra que
 * devolvem `int` seguem a mesma ideia. As que devolvem `uint8_t *`
 * devolvem `NULL` em erro (ver a documentação de cada uma).
 * @warning Nesta revisão do repositório, o grupo de arquivamento (compressão,
 * extração, listagem, teste, LZ/LZH/byte-prediction, varint,
 * filelist, `zupt_strerror`, `zupt_codec_name`, `zupt_default_options`,
 * `zupt_format_size`, `zupt_resolve_auto_codec`, imagem de disco e
 * deduplicação) é declarado neste cabeçalho, mas <b>não possui
 * definição em `src/`</b>. A cada uma dessas funções está anexada a
 * mesma nota. Ver docs/doxygen/limitacoes.md e
 * docs/doxygen/inventario.md.
 * @warning Há divergência de versionamento declarativo nesta árvore:
 * `ZUPT_VERSION_STRING` é "2.1.5" aqui; `LIBZUPT_VERSION_STRING` é
 * "1.0.15" em libzupt_version.h e é o valor usado pelo CMakeLists.txt
 * para `PROJECT_VERSION`/SOVERSION. As duas são documentadas como
 * estão, não harmonizadas.
 * @see include/libzupt_version.h, include/zupt_cxx.h, include/zupt_mlkem.h,
 * include/zupt_x25519.h, include/zupt_acsl.h, docs/FORMAT.md
 * @endcond
 * @cond INGLES
 * @file   zupt.h
 * @brief  Public header of libzupt: format constants, cryptographic primitives and archiving API.
 * @details This is the library's umbrella include file. It declares:
 * - format macros (magic, format versions, limits, global flags,
 * cipher types, block types, codec identifiers);
 * - the on-disk format structures (`zupt_archive_header_t`,
 * `zupt_footer_t`), packed byte by byte and serialized in
 * little-endian;
 * - the in-memory structures (`zupt_index_entry_t`, `zupt_block_t`,
 * `zupt_keyring_t`, `zupt_filelist_t`, `zupt_options_t`);
 * - `static inline` helpers: little-endian serialization, secure
 * memory wiping and regular file testing;
 * - the cryptographic primitives implemented in this tree
 * (SHA-256, AES-256, HMAC-SHA256, PBKDF2, AES-256-CTR, key derivation,
 * Encrypt-then-MAC envelope, XXH64, randomness,
 * memory locking);
 * - the archiving, compression, extraction, deduplication and
 * disk image API.
 *
 * Endianness: the multibyte numeric fields of the on-disk format are
 * little-endian. The `zupt_le*_put`/`zupt_le*_get` helpers perform the
 * byte-by-byte conversion, so the result does not depend on the host's
 * endianness. The `zupt_archive_header_t` and `zupt_footer_t` types use
 * the `pack(push,1)` pragma: writing them as a single block of bytes only
 * produces little-endian on a little-endian host, which is why
 * serialization uses the helpers above instead of writing the
 * structs directly.
 *
 * Return convention: most of the API returns `zupt_error_t`
 * (0 = success, negative = error). The cipher-group functions that
 * return `int` follow the same idea. Those returning `uint8_t *`
 * return `NULL` on error (see each one's documentation).
 * @warning In this revision of the repository, the archiving group (compression,
 * extraction, listing, testing, LZ/LZH/byte-prediction, varints,
 * filelist, `zupt_strerror`, `zupt_codec_name`, `zupt_default_options`,
 * `zupt_format_size`, `zupt_resolve_auto_codec`, disk image and
 * deduplication) is declared in this header, but <b>has no
 * definition in `src/`</b>. Each of these functions carries the
 * same note. See docs/doxygen/limitacoes.md and
 * docs/doxygen/inventario.md.
 * @warning There is declarative version divergence in this tree:
 * `ZUPT_VERSION_STRING` is "2.1.5" here; `LIBZUPT_VERSION_STRING` is
 * "1.0.15" in libzupt_version.h and that is the value used by CMakeLists.txt
 * for `PROJECT_VERSION`/SOVERSION. Both are documented as
 * they are, not harmonized.
 * @see include/libzupt_version.h, include/zupt_cxx.h, include/zupt_mlkem.h,
 * include/zupt_x25519.h, include/zupt_acsl.h, docs/FORMAT.md
 * @endcond */
#ifndef ZUPT_H
#define ZUPT_H

/* Feature test macros — must precede all system includes.
 * _DEFAULT_SOURCE gives us lstat() on glibc without -D_GNU_SOURCE. */
/**
 * @cond PORT
 * @def _DEFAULT_SOURCE
 * @brief Macro de teste de recurso da glibc, definido quando ausente.
 * @details Definido como 1 apenas quando nem `_DEFAULT_SOURCE` nem
 * `_GNU_SOURCE` já foram definidos, e sempre antes de qualquer
 * inclusão de sistema. É o que torna `lstat()` visível na glibc sem
 * exigir `-D_GNU_SOURCE` no compile do consumidor.
 * @note Não altera o contrato das funções: apenas expõe interfaces POSIX.
 * @endcond
 * @cond INGLES
 * @def _DEFAULT_SOURCE
 * @brief glibc feature test macro, defined when absent.
 * @details Defined as 1 only when neither `_DEFAULT_SOURCE` nor
 * `_GNU_SOURCE` has already been defined, and always before any
 * system include. It is what makes `lstat()` visible in glibc without
 * requiring `-D_GNU_SOURCE` in the consumer's compile.
 * @note It does not change the functions' contract: it only exposes POSIX interfaces.
 * @endcond */
#if !defined(_DEFAULT_SOURCE) && !defined(_GNU_SOURCE)
  #define _DEFAULT_SOURCE 1
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

/**
 * @cond PORT
 * @def ZUPT_PATH_SEP
 * @brief Separador de componentes de caminho da plataforma.
 * @details Recebe a barra invertida quando compilado para Windows (`_WIN32`)
 * e a barra normal nos demais sistemas. Definido dentro do mesmo
 * condição de pré-processador que escolhe os cabeçalhos de sistema, por isso sempre
 * existe em qualquer configuração. Não há normalização de caminhos
 * em disco: o arquivo guarda o separador do sistema que o criou.
 * @endcond
 * @cond INGLES
 * @def ZUPT_PATH_SEP
 * @brief Platform path component separator.
 * @details It receives the backslash when compiled for Windows (`_WIN32`)
 * and the forward slash on other systems. It is defined within the same
 * preprocessor condition that selects the system headers, so it always
 * exists in any configuration. There is no path normalization
 * on disk: the file keeps the separator of the system that created it.
 * @endcond */
/**
 * @cond PORT
 * @def zupt_mkdir(p)
 * @brief Cria o diretório `p` com permissões de padrão POSIX (0755).
 * @details Em `_WIN32` expande para `_mkdir(p)`, que ignora o argumento de
 * modo; nos demais sistemas para `mkdir(p, 0755)`. Não há
 * tratamento de erro embutido: o chamador deve observar o valor
 * devolvido pela chamada de sistema.
 * @param[in] p Caminho do diretório a criar.
 * @endcond
 * @cond INGLES
 * @def zupt_mkdir(p)
 * @brief Creates directory `p` with standard POSIX permissions (0755).
 * @details Under `_WIN32` it expands to `_mkdir(p)`, which ignores the mode
 * argument; on other systems to `mkdir(p, 0755)`. There is no
 * built-in error handling: the caller must observe the value
 * returned by the system call.
 * @param[in] p Path of the directory to create.
 * @endcond */
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

/**
 * @cond PORT
 * @def ZUPT_VERSION_STRING
 * @brief Cadeia de versão declarada por este cabeçalho (`"2.1.5"`).
 * @warning Este valor <b>não</b> é a versão da biblioteca compartilhada.
 * `include/libzupt_version.h` define `LIBZUPT_VERSION_STRING` como
 * `"1.0.15"`, e é esse valor que o CMakeLists.txt usa para
 * `PROJECT_VERSION` e para o SOVERSION do objeto compartilhado.
 * `CHANGES.md`/`README.md` mencionam ainda `2.0.0`. Nesta revisão as
 * divergências são documentadas como estão, não corrigidas.
 * @see LIBZUPT_VERSION_STRING
 * @endcond
 * @cond INGLES
 * @def ZUPT_VERSION_STRING
 * @brief Version string declared by this header (`"2.1.5"`).
 * @warning This value <b>is not</b> the shared library's version.
 * `include/libzupt_version.h` defines `LIBZUPT_VERSION_STRING` as
 * `"1.0.15"`, and that is the value CMakeLists.txt uses for
 * `PROJECT_VERSION` and for the shared object's SOVERSION.
 * `CHANGES.md`/`README.md` also mention `2.0.0`. In this revision the
 * divergences are documented as they are, not corrected.
 * @see LIBZUPT_VERSION_STRING
 * @endcond */
#define ZUPT_VERSION_STRING "2.1.5"
/**
 * @cond PORT
 * @def ZUPT_FORMAT_MAJOR
 * @brief Componente maior da versão de formato de arquivo suportada (1).
 * @details É escrito em `version_major` de @ref zupt_archive_header_t.
 * @endcond
 * @cond INGLES
 * @def ZUPT_FORMAT_MAJOR
 * @brief Major component of the supported file format version (1).
 * @details It is written to `version_major` of @ref zupt_archive_header_t.
 * @endcond */
#define ZUPT_FORMAT_MAJOR   1
/**
 * @cond PORT
 * @def ZUPT_FORMAT_MINOR
 * @brief Componente menor da versão de formato de arquivo suportada (4).
 * @details É escrito em `version_minor` de @ref zupt_archive_header_t.
 * A combinação `1.4` identifica o layout descrito em
 * @ref page-formato.
 * @endcond
 * @cond INGLES
 * @def ZUPT_FORMAT_MINOR
 * @brief Minor component of the supported file format version (4).
 * @details It is written to `version_minor` of @ref zupt_archive_header_t.
 * The `1.4` combination identifies the layout described in
 * @ref page-formato.
 * @endcond */
#define ZUPT_FORMAT_MINOR   4

/**
 * @cond PORT
 * @def ZUPT_MAGIC_0
 * @brief Primeiro byte da assinatura de 6 bytes do cabeçalho de arquivo: `0x5A` (`'Z'`).
 * @details Os seis bytes, nesta ordem, são `0x5A 0x55 0x50 0x54` (a cadeia
 * `"ZUPT"`), seguidos de `0x1A` (byte de controle ASCII de
 * substituto/fim de arquivo) e de um byte nulo de folga. São gravados
 * no campo `magic` de @ref zupt_archive_header_t e servem para
 * reconhecer o arquivo e rejeitar versões incompatíveis de leitura.
 * @endcond
 * @cond INGLES
 * @def ZUPT_MAGIC_0
 * @brief First byte of the file header's 6-byte signature: `0x5A` (`'Z'`).
 * @details The six bytes, in this order, are `0x5A 0x55 0x50 0x54` (the string
 * `"ZUPT"`), followed by `0x1A` (the ASCII control byte for
 * substitute/end of file) and a null padding byte. They are written
 * to the `magic` field of @ref zupt_archive_header_t and serve to
 * recognize the file and reject incompatible read versions.
 * @endcond */
#define ZUPT_MAGIC_0  0x5A
/**
 * @cond PORT
 * @brief Segundo byte da assinatura do cabeçalho: `0x55` (`'U'`).
 * @endcond
 * @cond INGLES
 * @brief Second byte of the header signature: `0x55` (`'U'`).
 * @endcond */
#define ZUPT_MAGIC_1  0x55
/**
 * @cond PORT
 * @brief Terceiro byte da assinatura do cabeçalho: `0x50` (`'P'`).
 * @endcond
 * @cond INGLES
 * @brief Third byte of the header signature: `0x50` (`'P'`).
 * @endcond */
#define ZUPT_MAGIC_2  0x50
/**
 * @cond PORT
 * @brief Quarto byte da assinatura do cabeçalho: `0x54` (`'T'`).
 * @endcond
 * @cond INGLES
 * @brief Fourth byte of the header signature: `0x54` (`'T'`).
 * @endcond */
#define ZUPT_MAGIC_3  0x54
/**
 * @cond PORT
 * @brief Quinto byte da assinatura do cabeçalho: `0x1A` (controle ASCII `EOF`/substituto).
 * @endcond
 * @cond INGLES
 * @brief Fifth byte of the header signature: `0x1A` (ASCII control `EOF`/substitute).
 * @endcond */
#define ZUPT_MAGIC_4  0x1A
/**
 * @cond PORT
 * @brief Sexto byte da assinatura do cabeçalho: `0x00` (folga de terminador).
 * @endcond
 * @cond INGLES
 * @brief Sixth byte of the header signature: `0x00` (terminator padding).
 * @endcond */
#define ZUPT_MAGIC_5  0x00

/**
 * @cond PORT
 * @def ZUPT_BLOCK_MAGIC_0
 * @brief Primeiro byte da assinatura de 2 bytes que precede cada bloco do arquivo: `0xBB`.
 * @details Combinado com @ref ZUPT_BLOCK_MAGIC_1 forma `0xBB 0x01`. Serve para
 * delimitar e recuperar o início de um bloco durante a leitura, por
 * exemplo ao reconstruir o índice a partir do corpo do arquivo, sem
 * usar o rodapé.
 * @endcond
 * @cond INGLES
 * @def ZUPT_BLOCK_MAGIC_0
 * @brief First byte of the 2-byte signature that precedes each file block: `0xBB`.
 * @details Combined with @ref ZUPT_BLOCK_MAGIC_1 it forms `0xBB 0x01`. It serves to
 * mark and recover the start of a block while reading, for
 * example when rebuilding the index from the file body, without
 * using the footer.
 * @endcond */
#define ZUPT_BLOCK_MAGIC_0 0xBB
/**
 * @cond PORT
 * @brief Segundo byte da assinatura de bloco: `0x01`. Ver @ref ZUPT_BLOCK_MAGIC_0.
 * @endcond
 * @cond INGLES
 * @brief Second byte of the block signature: `0x01`. See @ref ZUPT_BLOCK_MAGIC_0.
 * @endcond */
#define ZUPT_BLOCK_MAGIC_1 0x01

/**
 * @cond PORT
 * @def ZUPT_MAX_PATH
 * @brief Comprimento máximo, em bytes, de um caminho armazenado nas estruturas (4096).
 * @details Usado como dimensão de `path` em @ref zupt_index_entry_t e de
 * `keyfile` em @ref zupt_options_t. O valor inclui o terminador nulo:
 * um caminho de exatamente `ZUPT_MAX_PATH` bytes não cabe com o
 * terminador.
 * @endcond
 * @cond INGLES
 * @def ZUPT_MAX_PATH
 * @brief Maximum length, in bytes, of a path stored in the structures (4096).
 * @details Used as the dimension of `path` in @ref zupt_index_entry_t and of
 * `keyfile` in @ref zupt_options_t. The value includes the null terminator:
 * a path of exactly `ZUPT_MAX_PATH` bytes does not fit with the
 * terminator.
 * @endcond */
#define ZUPT_MAX_PATH         4096
/**
 * @cond PORT
 * @def ZUPT_MAX_FILES
 * @brief Limite superior de entradas de arquivo que a biblioteca pretende suportar (2.000.000).
 * @endcond
 * @cond INGLES
 * @def ZUPT_MAX_FILES
 * @brief Upper bound of file entries the library intends to support (2.000.000).
 * @endcond */
#define ZUPT_MAX_FILES        2000000
/**
 * @cond PORT
 * @def ZUPT_DEFAULT_BLOCK_SZ
 * @brief Tamanho de bloco usado quando o chamador não escolhe um: 4 MiB.
 * @endcond
 * @cond INGLES
 * @def ZUPT_DEFAULT_BLOCK_SZ
 * @brief Block size used when the caller does not choose one: 4 MiB.
 * @endcond */
#define ZUPT_DEFAULT_BLOCK_SZ (4 * 1024 * 1024)
/**
 * @cond PORT
 * @def ZUPT_MIN_BLOCK_SZ
 * @brief Menor tamanho de bloco aceito: 64 KiB.
 * @endcond
 * @cond INGLES
 * @def ZUPT_MIN_BLOCK_SZ
 * @brief Smallest accepted block size: 64 KiB.
 * @endcond */
#define ZUPT_MIN_BLOCK_SZ     (64 * 1024)
/**
 * @cond PORT
 * @def ZUPT_MAX_BLOCK_SZ
 * @brief Maior tamanho de bloco aceito: 256 MiB.
 * @details Os três limites acima são comparados ao campo `block_size` de
 * @ref zupt_options_t antes de comprimar. Blocos maiores implicam mais
 * memória no pico e menos redundância explorada entre blocos.
 * @endcond
 * @cond INGLES
 * @def ZUPT_MAX_BLOCK_SZ
 * @brief Largest accepted block size: 256 MiB.
 * @details The three limits above are compared against the `block_size` field of
 * @ref zupt_options_t before compressing. Larger blocks imply more
 * peak memory and less redundancy exploited across blocks.
 * @endcond */
#define ZUPT_MAX_BLOCK_SZ     (256 * 1024 * 1024)

/* Global flags */
/**
 * @cond PORT
 * @def ZUPT_FLAG_ENCRYPTED
 * @brief Flag global: o conteúdo do arquivo está cifrado (bit 0).
 * @details Bit 0 do campo `global_flags` de @ref zupt_archive_header_t. Quando
 * ligado, a leitura exige um @ref zupt_keyring_t válido (e, no modo
 * pós-quântico, o cabeçalho de cifra híbrida).
 * @endcond
 * @cond INGLES
 * @def ZUPT_FLAG_ENCRYPTED
 * @brief Global flag: the file content is encrypted (bit 0).
 * @details Bit 0 of the `global_flags` field of @ref zupt_archive_header_t. When
 * set, reading requires a valid @ref zupt_keyring_t (and, in post-quantum
 * mode, the hybrid cipher header).
 * @endcond */
#define ZUPT_FLAG_ENCRYPTED    (1u << 0)
/**
 * @cond PORT
 * @def ZUPT_FLAG_CKSUM_XXH64
 * @brief Flag reservada para soma de verificação XXH64; definida como zero.
 * @details Expande para `(0u << 5)`, ou seja, o valor resultante é `0`.
 * Operações bitwise que usam esta macro para ligar um bit de
 * `global_flags` não alteram o campo; o bit 5 portanto não é ocupado
 * por esta macro.
 * @warning Registrado como achado de documentação (não corrigido): a forma
 * provável era `(1u << 5)`. Ver @ref page-limitacoes.
 * @endcond
 * @cond INGLES
 * @def ZUPT_FLAG_CKSUM_XXH64
 * @brief Reserved flag for the XXH64 checksum; defined as zero.
 * @details It expands to `(0u << 5)`, that is, the resulting value is `0`.
 * Bitwise operations that use this macro to set a bit of
 * `global_flags` do not change the field; bit 5 is therefore not occupied
 * by this macro.
 * @warning Logged as a documentation finding (not corrected): the likely
 * form was `(1u << 5)`. See @ref page-limitacoes.
 * @endcond */
#define ZUPT_FLAG_CKSUM_XXH64  (0u << 5)
/**
 * @cond PORT
 * @def ZUPT_FLAG_SOLID
 * @brief Flag global: arquivo em modo sólido, com blocos compartilhando contexto de compressão (bit 1).
 * @details Indica que o arquivo foi produzido por @ref zupt_compress_solid;
 * nesse caso os blocos não são independentes quanto ao contexto do
 * codec e precisam ser decodificados na ordem de gravação.
 * @endcond
 * @cond INGLES
 * @def ZUPT_FLAG_SOLID
 * @brief Global flag: solid-mode file, whose blocks share compression context (bit 1).
 * @details Indicates that the file was produced by @ref zupt_compress_solid;
 * in that case the blocks are not independent with respect to the
 * codec's context and must be decoded in write order.
 * @endcond */
#define ZUPT_FLAG_SOLID        (1u << 1)
/**
 * @cond PORT
 * @def ZUPT_FLAG_MULTITHREADED
 * @brief Flag informativa: o arquivo foi produzido com compressão multinúcleo (bit 2).
 * @details Não altera a decodificação: um extrator serial consegue ler um
 * arquivo com este bit ligado.
 * @endcond
 * @cond INGLES
 * @def ZUPT_FLAG_MULTITHREADED
 * @brief Informational flag: the file was produced with multi-core compression (bit 2).
 * @details It does not change decoding: a serial extractor can read a file
 * with this bit set.
 * @endcond */
#define ZUPT_FLAG_MULTITHREADED (1u << 2) /* Informational: archive was produced with MT */
/**
 * @cond PORT
 * @def ZUPT_FLAG_PQ_HYBRID
 * @brief Flag global: cifra híbrida pós-quântica ML-KEM-768 + X25519 (bit 3).
 * @details Ligado quando a chave de sessão veio de
 * @ref zupt_hybrid_encrypt_init ou @ref zupt_hybrid_encrypt_init_mem,
 * e não de @ref zupt_derive_keys. Ver também
 * @ref ZUPT_ENC_PQ_HYBRID.
 * @endcond
 * @cond INGLES
 * @def ZUPT_FLAG_PQ_HYBRID
 * @brief Global flag: post-quantum hybrid cipher ML-KEM-768 + X25519 (bit 3).
 * @details Set when the session key came from
 * @ref zupt_hybrid_encrypt_init or @ref zupt_hybrid_encrypt_init_mem,
 * and not from @ref zupt_derive_keys. See also
 * @ref ZUPT_ENC_PQ_HYBRID.
 * @endcond */
#define ZUPT_FLAG_PQ_HYBRID    (1u << 3) /* Post-quantum hybrid encryption */
/**
 * @cond PORT
 * @def ZUPT_FLAG_FORMAT_STABLE
 * @brief Flag que marca o formato como congelado na v1.0 (bit 4).
 * @endcond
 * @cond INGLES
 * @def ZUPT_FLAG_FORMAT_STABLE
 * @brief Flag that marks the format as frozen at v1.0 (bit 4).
 * @endcond */
#define ZUPT_FLAG_FORMAT_STABLE (1u << 4) /* v1.0: format frozen */
/**
 * @cond PORT
 * @def ZUPT_FLAG_DEDUP
 * @brief Flag global: deduplicação no nível de bloco habilitada (bit 7).
 * @details Quando ligada, blocos repetidos podem ser gravados como
 * @ref ZUPT_BLOCK_DEDUP_REF em vez de uma cópia do payload.
 * @endcond
 * @cond INGLES
 * @def ZUPT_FLAG_DEDUP
 * @brief Global flag: block-level deduplication enabled (bit 7).
 * @details When set, repeated blocks may be written as
 * @ref ZUPT_BLOCK_DEDUP_REF instead of a copy of the payload.
 * @endcond */
#define ZUPT_FLAG_DEDUP        (1u << 7) /* Block-level deduplication enabled */

/* Encryption types (stored in encryption header block) */
/**
 * @cond PORT
 * @def ZUPT_ENC_PBKDF2
 * @brief Tipo de cifra por senha: PBKDF2-HMAC-SHA256 com AES-256-CTR + HMAC-SHA256 (`0x01`).
 * @details Valor gravado no campo de tipo do bloco de cabeçalho de cifra. As
 * chaves são derivadas de senha e salt por @ref zupt_pbkdf2_sha256 e
 * montadas em um @ref zupt_keyring_t por @ref zupt_derive_keys; o
 * número de iterações é o de @ref ZUPT_KDF_ITERATIONS, salvo quando o
 * arquivo grava valor diferente.
 * @endcond
 * @cond INGLES
 * @def ZUPT_ENC_PBKDF2
 * @brief Password cipher type: PBKDF2-HMAC-SHA256 with AES-256-CTR + HMAC-SHA256 (`0x01`).
 * @details Value written to the type field of the cipher header block. The
 * keys are derived from password and salt by @ref zupt_pbkdf2_sha256 and
 * assembled into a @ref zupt_keyring_t by @ref zupt_derive_keys; the
 * iteration count is that of @ref ZUPT_KDF_ITERATIONS, unless the
 * file stores a different value.
 * @endcond */
#define ZUPT_ENC_PBKDF2     0x01  /* Password-based: PBKDF2 → AES-256-CTR + HMAC */
/**
 * @cond PORT
 * @def ZUPT_ENC_PQ_HYBRID
 * @brief Tipo de cifra híbrida pós-quântica: KEM ML-KEM-768 + X25519 (`0x03`).
 * @details Valor gravado no campo de tipo do bloco de cabeçalho de cifra. A
 * chave de sessão vem de uma chave compartilhada híbrida (ML-KEM-768
 * sobre X25519) transportada no cabeçalho de cifra de 1137 bytes. Não
 * há senha: o segredo é a posse da chave privada.
 * @see zupt_hybrid_keygen, zupt_hybrid_encrypt_init, zupt_hybrid_decrypt_init,
 * ZUPT_FLAG_PQ_HYBRID
 * @endcond
 * @cond INGLES
 * @def ZUPT_ENC_PQ_HYBRID
 * @brief Post-quantum hybrid cipher type: ML-KEM-768 + X25519 KEM (`0x03`).
 * @details Value written to the type field of the cipher header block. The
 * session key comes from a hybrid shared key (ML-KEM-768
 * over X25519) carried in the 1137-byte cipher header. There is
 * no password: the secret is possession of the private key.
 * @see zupt_hybrid_keygen, zupt_hybrid_encrypt_init, zupt_hybrid_decrypt_init,
 * ZUPT_FLAG_PQ_HYBRID
 * @endcond */
#define ZUPT_ENC_PQ_HYBRID  0x03  /* ML-KEM-768 + X25519 hybrid KEM */

/**
 * @cond PORT
 * @def ZUPT_BLOCK_DATA
 * @brief Tipo de bloco `0x00`: bloco de dados, com o payload de um arquivo ou de uma imagem.
 * @details É o tipo mais frequente do contêiner; os demais tipos descrevem
 * metadados (índice, cabeçalho de cifra, referência de deduplicação).
 * @endcond
 * @cond INGLES
 * @def ZUPT_BLOCK_DATA
 * @brief Block type `0x00`: data block, holding the payload of a file or of an image.
 * @details It is the most frequent type in the container; the other types describe
 * metadata (index, cipher header, deduplication reference).
 * @endcond */
#define ZUPT_BLOCK_DATA       0x00
/**
 * @cond PORT
 * @def ZUPT_BLOCK_INDEX
 * @brief Tipo de bloco `0x02`: bloco que contém o índice do arquivo.
 * @details Sua posição em disco é registrada em `index_offset` do rodapé,
 * campo de @ref zupt_footer_t.
 * @endcond
 * @cond INGLES
 * @def ZUPT_BLOCK_INDEX
 * @brief Block type `0x02`: block that contains the file's index.
 * @details Its position on disk is recorded in the footer's `index_offset`
 * field, a field of @ref zupt_footer_t.
 * @endcond */
#define ZUPT_BLOCK_INDEX      0x02
/**
 * @cond PORT
 * @def ZUPT_BLOCK_ENC_HEADER
 * @brief Tipo de bloco (0x03) reservado ao cabeçalho de descriptografia.
 * @details Blocos de dados carregam um cabeçalho de 16 bytes em que este campo
 * identifica o que o payload representa; este tipo guarda os
 * parâmetros necessários para reconstituir a chave de sessão
 * (salto, iterações da KDF, chave envelopada).
 * @endcond
 * @cond INGLES
 * @def ZUPT_BLOCK_ENC_HEADER
 * @brief Block type (0x03) reserved for the decryption header.
 * @details Data blocks carry a 16-byte header in which this field
 * identifies what the payload represents; this type holds the
 * parameters needed to reconstitute the session key
 * (salt, KDF iterations, wrapped key).
 * @endcond */
#define ZUPT_BLOCK_ENC_HEADER 0x03
/**
 * @cond PORT
 * @def ZUPT_BLOCK_DEDUP_REF
 * @brief Tipo de bloco (0x04) que referencia um bloco já gravado.
 * @details O payload é composto apenas por 8 bytes com o deslocamento, em
 * disco, do bloco original — mecanismo de desduplicação.
 * @see ZUPT_DEDUP_MAX_ENTRIES
 * @endcond
 * @cond INGLES
 * @def ZUPT_BLOCK_DEDUP_REF
 * @brief Block type (0x04) that references a block already written.
 * @details The payload consists only of 8 bytes holding the offset, on
 * disk, of the original block — the deduplication mechanism.
 * @see ZUPT_DEDUP_MAX_ENTRIES
 * @endcond */
#define ZUPT_BLOCK_DEDUP_REF  0x04  /* Dedup reference: payload = 8B offset of original block */
/**
 * @cond PORT
 * @def ZUPT_BFLAG_ENCRYPTED
 * @brief Bit (1u &lt;&lt; 0) do campo `block_flags` do cabeçalho de um bloco.
 * @details Indica que o payload do bloco está cifrado. É independente dos
 * flags globais do arquivo (@ref ZUPT_FLAG_ENCRYPTED): o bloco do
 * cabeçalho de criptografia pode usar este bit ao transportar a
 * chave de sessão envelopada.
 * @endcond
 * @cond INGLES
 * @def ZUPT_BFLAG_ENCRYPTED
 * @brief Bit (1u &lt;&lt; 0) of the `block_flags` field of a block header.
 * @details Indicates that the block's payload is encrypted. It is independent
 * of the file's global flags (@ref ZUPT_FLAG_ENCRYPTED): the encryption header
 * block may use this bit when transporting the wrapped
 * session key.
 * @endcond */
#define ZUPT_BFLAG_ENCRYPTED  (1u << 0)
/**
 * @cond PORT
 * @def ZUPT_CODEC_STORE
 * @brief Identificador de codec (0x0000): dados armazenados sem compressão.
 * @details Usado quando o codec resultou em saída maior que a entrada.
 * @endcond
 * @cond INGLES
 * @def ZUPT_CODEC_STORE
 * @brief Codec identifier (0x0000): data stored without compression.
 * @details Used when the codec produced output larger than the input.
 * @endcond */
#define ZUPT_CODEC_STORE   0x0000
/**
 * @cond PORT
 * @def ZUPT_CODEC_ZUPT_LZ
 * @brief Identificador de codec (0x0008): compressão LZ77 própria.
 * @endcond
 * @cond INGLES
 * @def ZUPT_CODEC_ZUPT_LZ
 * @brief Codec identifier (0x0008): in-house LZ77 compression.
 * @endcond */
#define ZUPT_CODEC_ZUPT_LZ 0x0008
/**
 * @cond PORT
 * @def ZUPT_CODEC_ZUPT_LZH
 * @brief Identificador de codec (0x0009): LZ77 seguido de Huffman.
 * @endcond
 * @cond INGLES
 * @def ZUPT_CODEC_ZUPT_LZH
 * @brief Codec identifier (0x0009): LZ77 followed by Huffman.
 * @endcond */
#define ZUPT_CODEC_ZUPT_LZH 0x0009  /* LZ77 + Huffman */
/**
 * @cond PORT
 * @def ZUPT_CODEC_ZUPT_LZHP
 * @brief Identificador de codec (0x000A): LZ77 + Huffman + predição de bytes.
 * @details O comentário de @ref ZUPT_CODEC_ZUPT_LZHP no cabeçalho o aponta
 * como padrão da biblioteca.
 * @endcond
 * @cond INGLES
 * @def ZUPT_CODEC_ZUPT_LZHP
 * @brief Codec identifier (0x000A): LZ77 + Huffman + byte prediction.
 * @details The comment on @ref ZUPT_CODEC_ZUPT_LZHP in the header points to it
 * as the library's default.
 * @endcond */
#define ZUPT_CODEC_ZUPT_LZHP 0x000A /* LZ77 + Huffman + Byte Prediction (default) */
/**
 * @cond PORT
 * @def ZUPT_CODEC_VAPTVUPT
 * @brief Identificador de codec (0x0010): VaptVupt LZ com entropia ANS.
 * @endcond
 * @cond INGLES
 * @def ZUPT_CODEC_VAPTVUPT
 * @brief Codec identifier (0x0010): VaptVupt LZ with ANS entropy coding.
 * @endcond */
#define ZUPT_CODEC_VAPTVUPT  0x0010 /* VAPTVUPT: VaptVupt LZ + ANS entropy codec */
/**
 * @cond PORT
 * @def ZUPT_CODEC_AUTO
 * @brief Identificador de codec (0xFFFF): escolha automática pelo ambiente.
 * @details O comentário do cabeçalho resume a política a "VaptVupt se houver
 * AVX2, senão LZHP". A função que resolveria essa escolha,
 * @ref zupt_resolve_auto_codec, não possui definição em `src/`.
 * @endcond
 * @cond INGLES
 * @def ZUPT_CODEC_AUTO
 * @brief Codec identifier (0xFFFF): automatic choice by the environment.
 * @details The header comment sums the policy up as "VaptVupt if AVX2 is
 * available, otherwise LZHP". The function that would resolve this choice,
 * @ref zupt_resolve_auto_codec, has no definition in `src/`.
 * @endcond */
#define ZUPT_CODEC_AUTO      0xFFFF /* Auto-detect: VaptVupt if AVX2, else LZHP */
/**
 * @cond PORT
 * @def ZUPT_SALT_SIZE
 * @brief Tamanho do salto usado pela derivação de chave a partir de senha: 32 bytes.
 * @details É o tamanho lido/escrito por @ref zupt_encrypt_buffer e
 * @ref zupt_decrypt_buffer e o esperado por
 * @ref zupt_derive_keys. Aleatório por arquivo, gerado por
 * @ref zupt_random_bytes.
 * @endcond
 * @cond INGLES
 * @def ZUPT_SALT_SIZE
 * @brief Salt size used by password-based key derivation: 32 bytes.
 * @details It is the size read/written by @ref zupt_encrypt_buffer and
 * @ref zupt_decrypt_buffer and the one expected by
 * @ref zupt_derive_keys. Random per file, generated by
 * @ref zupt_random_bytes.
 * @endcond */
#define ZUPT_SALT_SIZE       32
/**
 * @cond PORT
 * @def ZUPT_NONCE_SIZE
 * @brief Tamanho do vetor de não-repetição do AES-256-CTR: 16 bytes.
 * @endcond
 * @cond INGLES
 * @def ZUPT_NONCE_SIZE
 * @brief AES-256-CTR nonce size: 16 bytes.
 * @endcond */
#define ZUPT_NONCE_SIZE      16
/**
 * @cond PORT
 * @def ZUPT_HMAC_SIZE
 * @brief Tamanho da tag HMAC-SHA256 que protege o payload cifrado: 32 bytes.
 * @endcond
 * @cond INGLES
 * @def ZUPT_HMAC_SIZE
 * @brief Size of the HMAC-SHA256 tag that protects the encrypted payload: 32 bytes.
 * @endcond */
#define ZUPT_HMAC_SIZE       32
/**
 * @cond PORT
 * @def ZUPT_AES_KEY_SIZE
 * @brief Tamanho da chave AES usada pela biblioteca: 32 bytes (AES-256).
 * @endcond
 * @cond INGLES
 * @def ZUPT_AES_KEY_SIZE
 * @brief Size of the AES key used by the library: 32 bytes (AES-256).
 * @endcond */
#define ZUPT_AES_KEY_SIZE    32
/**
 * @cond PORT
 * @def ZUPT_KDF_ITERATIONS
 * @brief Iterações da PBKDF2-HMAC-SHA256 aplicada a senhas: 600000.
 * @details Custo de derivar uma chave de senha: o número foi escolhido para
 * dificultar ataques offline; qualquer mudança é incompatível com
 * arquivos já gravados.
 * @endcond
 * @cond INGLES
 * @def ZUPT_KDF_ITERATIONS
 * @brief Iterations of the PBKDF2-HMAC-SHA256 applied to passwords: 600000.
 * @details Cost of deriving a key from a password: the number was chosen to
 * hinder offline attacks; any change is incompatible with
 * files already written.
 * @endcond */
#define ZUPT_KDF_ITERATIONS  600000
/**
 * @cond PORT
 * @enum   zupt_error_t
 * @brief  Códigos de retorno usados pela maioria das funções da biblioteca.
 * @details Todos os erros são negativos; @ref ZUPT_OK vale zero. A tabela
 * abaixo resume o significado de cada constante.
 *
 * | Constante | Valor | Significado |
 * |---|---|---|
 * | ZUPT_OK | 0 | Operação concluída com sucesso. |
 * | ZUPT_ERR_IO | -1 | Falha de E/S: abrir, ler, escrever ou obter tamanho. |
 * | ZUPT_ERR_CORRUPT | -2 | Estrutura interna inconsistente ao ler o arquivo. |
 * | ZUPT_ERR_BAD_MAGIC | -3 | Magic/assinatura ausente ou diferente do esperado. |
 * | ZUPT_ERR_BAD_VERSION | -4 | Versão de formato (arquivo, chave ou envelope) não suportada. |
 * | ZUPT_ERR_BAD_CHECKSUM | -5 | Soma de verificação não confere. |
 * | ZUPT_ERR_NOMEM | -6 | Falha de alocação de memória. |
 * | ZUPT_ERR_OVERFLOW | -7 | Tamanho/contagem excede o máximo suportado. |
 * | ZUPT_ERR_INVALID | -8 | Argumento, tamanho ou estado inválido. |
 * | ZUPT_ERR_NOT_FOUND | -9 | Item procurado não existe (por exemplo uma chave). |
 * | ZUPT_ERR_UNSUPPORTED | -10 | Operação, codec ou parâmetro não suportado nesta build. |
 * | ZUPT_ERR_AUTH_FAIL | -11 | Autenticação falhou: MAC/envelope não validou. |
 *
 * @note    Nem toda função devolui @ref zupt_error_t; as que alocam memória
 * devolvem ponteiro e indicam falha com `NULL`, e as de verificação
 * criptográfica devolvem inteiro não-nulo em caso de falha.
 * @endcond
 * @cond INGLES
 * @enum   zupt_error_t
 * @brief  Return codes used by most of the library's functions.
 * @details All errors are negative; @ref ZUPT_OK is zero. The table
 * below summarizes the meaning of each constant.
 *
 * | Constant | Value | Meaning |
 * |---|---|---|
 * | ZUPT_OK | 0 | Operation completed successfully. |
 * | ZUPT_ERR_IO | -1 | I/O failure: open, read, write or get size. |
 * | ZUPT_ERR_CORRUPT | -2 | Inconsistent internal structure while reading the file. |
 * | ZUPT_ERR_BAD_MAGIC | -3 | Magic/signature missing or different from the expected one. |
 * | ZUPT_ERR_BAD_VERSION | -4 | Format version (file, key or envelope) not supported. |
 * | ZUPT_ERR_BAD_CHECKSUM | -5 | Checksum does not match. |
 * | ZUPT_ERR_NOMEM | -6 | Memory allocation failure. |
 * | ZUPT_ERR_OVERFLOW | -7 | Size/count exceeds the supported maximum. |
 * | ZUPT_ERR_INVALID | -8 | Invalid argument, size or state. |
 * | ZUPT_ERR_NOT_FOUND | -9 | Requested item does not exist (for example a key). |
 * | ZUPT_ERR_UNSUPPORTED | -10 | Operation, codec or parameter not supported in this build. |
 * | ZUPT_ERR_AUTH_FAIL | -11 | Authentication failed: MAC/envelope did not validate. |
 *
 * @note    Not every function returns @ref zupt_error_t; those that allocate memory
 * return a pointer and indicate failure with `NULL`, and those performing
 * cryptographic verification return a non-zero integer on failure.
 * @endcond */

typedef enum {
    /**
     * @cond PORT
     * Sucesso. Único valor não negativo do enumerado.
     * @endcond
     * @cond INGLES
     * Success. The only non-negative value in the enumeration.
     * @endcond */
    ZUPT_OK = 0,
    /**
     * @cond PORT
     * Falha de leitura ou escrita em disco.
     * @endcond
     * @cond INGLES
     * Failure reading from or writing to disk.
     * @endcond */
    ZUPT_ERR_IO = -1,
    /**
     * @cond PORT
     * Estrutura interna do contêiner inconsistente.
     * @endcond
     * @cond INGLES
     * Inconsistent internal structure of the container.
     * @endcond */
    ZUPT_ERR_CORRUPT = -2,
    /**
     * @cond PORT
     * Magic de arquivo ou de bloco inválido.
     * @endcond
     * @cond INGLES
     * Invalid file or block magic.
     * @endcond */
    ZUPT_ERR_BAD_MAGIC = -3,
    /**
     * @cond PORT
     * Versão de formato não suportada.
     * @endcond
     * @cond INGLES
     * Unsupported format version.
     * @endcond */
    ZUPT_ERR_BAD_VERSION = -4,
    /**
     * @cond PORT
     * Checksum divergente do conteúdo lido.
     * @endcond
     * @cond INGLES
     * Checksum divergent from the content read.
     * @endcond */
    ZUPT_ERR_BAD_CHECKSUM = -5,
    /**
     * @cond PORT
     * Alocação de memória falhou.
     * @endcond
     * @cond INGLES
     * Memory allocation failed.
     * @endcond */
    ZUPT_ERR_NOMEM = -6,
    /**
     * @cond PORT
     * Saída maior que a capacidade informada pelo chamador.
     * @endcond
     * @cond INGLES
     * Output larger than the capacity reported by the caller.
     * @endcond */
    ZUPT_ERR_OVERFLOW = -7,
    /**
     * @cond PORT
     * Argumento inválido, por exemplo ponteiro `NULL` onde não é aceito.
     * @endcond
     * @cond INGLES
     * Invalid argument, for example a `NULL` pointer where it is not accepted.
     * @endcond */
    ZUPT_ERR_INVALID = -8,
    /**
     * @cond PORT
     * Entrada ou arquivo solicitado não existe.
     * @endcond
     * @cond INGLES
     * Requested entry or file does not exist.
     * @endcond */
    ZUPT_ERR_NOT_FOUND = -9,
    /**
     * @cond PORT
     * Recurso solicitado não implementado nesta versão.
     * @endcond
     * @cond INGLES
     * Requested feature not implemented in this version.
     * @endcond */
    ZUPT_ERR_UNSUPPORTED = -10,
    /**
     * @cond PORT
     * Autenticação falhou: o HMAC do bloco não confere.
     * @endcond
     * @cond INGLES
     * Authentication failed: the block's HMAC does not match.
     * @endcond */
    ZUPT_ERR_AUTH_FAIL = -11,
} zupt_error_t;


/* ─── On-disk (packed LE) ─── */
/**
 * @cond PORT
 * @struct zupt_archive_header_t
 * @brief  Cabeçalho fixo de 64 bytes no início de todo arquivo da biblioteca.
 * @details Estrutura empacotada sem alinhamento (o pragma `pack(push,1)`),
 * pensada para espelhar byte a byte o que está em disco. Campos
 * numéricos multibyte são little-endian no arquivo: a escrita/leitura
 * correta em hosts big-endian depende dos helpers
 * @ref zupt_le16_put / @ref zupt_le32_put / @ref zupt_le64_put e seus
 * equivalentes de leitura, e não de copiar este struct como um bloco.
 * @note    O tamanho esperado é 64 bytes por construção do empacotamento.
 * @endcond
 * @cond INGLES
 * @struct zupt_archive_header_t
 * @brief  Fixed 64-byte header at the start of every file of the library.
 * @details Packed structure without alignment (the `pack(push,1)` pragma),
 * meant to mirror the bytes on disk one by one. Multibyte numeric
 * fields are little-endian in the file: correct writing/reading
 * on big-endian hosts depends on the helpers
 * @ref zupt_le16_put / @ref zupt_le32_put / @ref zupt_le64_put and their
 * reading counterparts, and not on copying this struct as a block.
 * @note    The expected size is 64 bytes by the construction of the packing.
 * @endcond */
#pragma pack(push, 1)
typedef struct {
    /**
     * @cond PORT
     * Magic do arquivo: os bytes de ::ZUPT_MAGIC_0 a ::ZUPT_MAGIC_5.
     * @endcond
     * @cond INGLES
     * File magic: the bytes from ::ZUPT_MAGIC_0 to ::ZUPT_MAGIC_5.
     * @endcond */
    uint8_t  magic[6];
    /**
     * @cond PORT
     * Versão do formato, separada em byte alto e byte baixo.
     * @endcond
     * @cond INGLES
     * Format version, split into high byte and low byte.
     * @endcond */
    /**
     * @cond PORT
     * Byte alto da versão do formato.
     * @endcond
     * @cond INGLES
     * High byte of the format version.
     * @endcond */
    uint8_t  version_major,
                 /**
                  * @cond PORT
                  * Byte baixo da versão do formato.
                  * @endcond
                  * @cond INGLES
                  * Low byte of the format version.
                  * @endcond */
                 version_minor;
    /**
     * @cond PORT
     * Flags globais, entre ::ZUPT_FLAG_ENCRYPTED e ::ZUPT_FLAG_DISK_IMAGE.
     * @endcond
     * @cond INGLES
     * Global flags, between ::ZUPT_FLAG_ENCRYPTED and ::ZUPT_FLAG_DISK_IMAGE.
     * @endcond */
    uint32_t global_flags;
    /**
     * @cond PORT
     * Timestamp Unix de criação, em segundos.
     * @endcond
     * @cond INGLES
     * Unix creation timestamp, in seconds.
     * @endcond */
    uint64_t creation_time;
    /**
     * @cond PORT
     * Identificador de 16 bytes da instância de arquivo.
     * @endcond
     * @cond INGLES
     * 16-byte identifier of the file instance.
     * @endcond */
    uint8_t  archive_id[16];
    /**
     * @cond PORT
     * Deslocamento do cabeçalho de criptografia, ou 0 quando não criptografado.
     * @endcond
     * @cond INGLES
     * Offset of the encryption header, or 0 when not encrypted.
     * @endcond */
    uint64_t encryption_header_off;
    /**
     * @cond PORT
     * Deslocamento do comentário do arquivo, ou 0 quando não há comentário.
     * @endcond
     * @cond INGLES
     * Offset of the file comment, or 0 when there is no comment.
     * @endcond */
    uint64_t comment_offset;
    /**
     * @cond PORT
     * Zona reservada, sempre zero na escrita.
     * @endcond
     * @cond INGLES
     * Reserved area, always zero when written.
     * @endcond */
    uint8_t  reserved[12];
} zupt_archive_header_t; /* 64 bytes */

/**
 * @cond PORT
 * @struct zupt_footer_t
 * @brief  Rodapé fixo de 32 bytes no fim do arquivo, usado para localizar o índice.
 * @details Empacotado como o cabeçalho. A leitura típica de um arquivo começa
 * aqui: o leitor vai ao fim, confere `footer_magic`, usa
 * `index_offset` para reler o bloco de índice e então compara
 * `archive_checksum`.
 * @endcond
 * @cond INGLES
 * @struct zupt_footer_t
 * @brief  Fixed 32-byte footer at the end of the file, used to locate the index.
 * @details Packed like the header. The typical read of a file starts
 * here: the reader goes to the end, checks `footer_magic`, uses
 * `index_offset` to reread the index block and then compares
 * `archive_checksum`.
 * @endcond */
typedef struct {
    /**
     * @cond PORT
     * Deslocamento, em bytes a partir do início do arquivo, do bloco de índice.
     * @endcond
     * @cond INGLES
     * Offset, in bytes from the start of the file, of the index block.
     * @endcond */
    uint64_t index_offset;
    /**
     * @cond PORT
     * Total de blocos de dados registrados no arquivo.
     * @endcond
     * @cond INGLES
     * Total number of data blocks registered in the file.
     * @endcond */
    uint64_t total_blocks;
    /**
     * @cond PORT
     * CRC-32 calculado sobre todo o arquivo, exceto os 4 bytes deste campo.
     * @endcond
     * @cond INGLES
     * CRC-32 computed over the whole file, except the 4 bytes of this field.
     * @endcond */
    uint64_t archive_checksum;
    /**
     * @cond PORT
     * Magic do rodapé: a sequência ASCII "ZEND".
     * @endcond
     * @cond INGLES
     * Footer magic: the ASCII sequence "ZEND".
     * @endcond */
    uint8_t  footer_magic[4]; /* "ZEND" */
    /**
     * @cond PORT
     * Versão do rodapé, no formato `(major << 8) | minor`.
     * @endcond
     * @cond INGLES
     * Footer version, in the form `(major << 8) | minor`.
     * @endcond */
    uint32_t footer_version;
} zupt_footer_t; /* 32 bytes */
#pragma pack(pop)

/* ─── In-memory ─── */
/**
 * @cond PORT
 * @struct zupt_index_entry_t
 * @brief  Entrada da tabela de índice: um arquivo (ou imagem) armazenado.
 * @details Representação em memória; não corresponde a um layout em disco. O
 * índice físico é o bloco @ref ZUPT_BLOCK_INDEX, gravado em formato
 * próprio e lido a partir de @ref zupt_footer_t::index_offset.
 * @endcond
 * @cond INGLES
 * @struct zupt_index_entry_t
 * @brief  Index table entry: a file (or image) stored in the archive.
 * @details In-memory representation; it does not correspond to an on-disk layout. The
 * physical index is the @ref ZUPT_BLOCK_INDEX block, written in its own
 * format and read from @ref zupt_footer_t::index_offset.
 * @endcond */
typedef struct {
    /**
     * @cond PORT
     * Caminho lógico do arquivo na entrada.
     * @endcond
     * @cond INGLES
     * Logical path of the file in the entry.
     * @endcond */
    char path[ZUPT_MAX_PATH];
    /**
     * @cond PORT
     * Tamanho original do arquivo, em bytes.
     * @endcond
     * @cond INGLES
     * Original file size, in bytes.
     * @endcond */
    uint64_t uncompressed_size,
                 /**
                  * @cond PORT
                  * Tamanho do arquivo após compressão, em bytes.
                  * @endcond
                  * @cond INGLES
                  * File size after compression, in bytes.
                  * @endcond */
                 compressed_size;
    /**
     * @cond PORT
     * Timestamp Unix da última modificação.
     * @endcond
     * @cond INGLES
     * Unix timestamp of the last modification.
     * @endcond */
    uint64_t modification_time,
                 /**
                  * @cond PORT
                  * Hash de conteúdo usado em deduplicação.
                  * @endcond
                  * @cond INGLES
                  * Content hash used in deduplication.
                  * @endcond */
                 content_hash;
    /**
     * @cond PORT
     * Deslocamento do primeiro bloco de dados do arquivo.
     * @endcond
     * @cond INGLES
     * Offset of the file's first data block.
     * @endcond */
    uint64_t first_block_offset;
    /**
     * @cond PORT
     * Quantidade de blocos de dados desta entrada.
     * @endcond
     * @cond INGLES
     * Number of data blocks in this entry.
     * @endcond */
    uint32_t block_count,
                 /**
                  * @cond PORT
                  * Atributos da entrada; a biblioteca não os interpreta.
                  * @endcond
                  * @cond INGLES
                  * Entry attributes; the library does not interpret them.
                  * @endcond */
                 attributes;
} zupt_index_entry_t;

/**
 * @cond PORT
 * @struct zupt_block_t
 * @brief  Bloco lido ou a ser gravado: cabeçalho de bloco + payload em memória.
 * @details `payload` aponta para o conteúdo comprimido (e possivelmente cifrado)
 * tal como está em disco. A decodificação é feita por
 * @ref decompress_block, que trata cifra e codec.
 * @endcond
 * @cond INGLES
 * @struct zupt_block_t
 * @brief  Block read or to be written: block header + payload in memory.
 * @details `payload` points to the compressed (and possibly encrypted) content
 * as it is on disk. Decoding is done by
 * @ref decompress_block, which handles cipher and codec.
 * @endcond */
typedef struct {
    /**
     * @cond PORT
     * Tipo do bloco: ::ZUPT_BLOCK_DATA, ::ZUPT_BLOCK_INDEX, ::ZUPT_BLOCK_ENC_HEADER ou ::ZUPT_BLOCK_DEDUP_REF.
     * @endcond
     * @cond INGLES
     * Block type: ::ZUPT_BLOCK_DATA, ::ZUPT_BLOCK_INDEX, ::ZUPT_BLOCK_ENC_HEADER or ::ZUPT_BLOCK_DEDUP_REF.
     * @endcond */
    uint8_t block_type;
    /**
     * @cond PORT
     * Codec usado neste bloco, um dos códigos `ZUPT_CODEC_*`.
     * @endcond
     * @cond INGLES
     * Codec used in this block, one of the `ZUPT_CODEC_*` codes.
     * @endcond */
    uint16_t codec_id,
                 /**
                  * @cond PORT
                  * Flags de bloco; hoje o único bit definido é ::ZUPT_BFLAG_ENCRYPTED.
                  * @endcond
                  * @cond INGLES
                  * Block flags; today the only defined bit is ::ZUPT_BFLAG_ENCRYPTED.
                  * @endcond */
                 block_flags;
    /**
     * @cond PORT
     * Tamanho do bloco descomprimido, em bytes.
     * @endcond
     * @cond INGLES
     * Uncompressed block size, in bytes.
     * @endcond */
    uint64_t uncompressed_size,
                 /**
                  * @cond PORT
                  * Tamanho do bloco como gravado, em bytes.
                  * @endcond
                  * @cond INGLES
                  * Block size as written, in bytes.
                  * @endcond */
                 compressed_size,
                 /**
                  * @cond PORT
                  * Checksum de 32 bits do conteúdo descomprimido.
                  * @endcond
                  * @cond INGLES
                  * 32-bit checksum of the uncompressed content.
                  * @endcond */
                 checksum;
    /**
     * @cond PORT
     * Ponteiro para o conteúdo do bloco, ou NULL quando não carregado.
     * @endcond
     * @cond INGLES
     * Pointer to the block content, or NULL when not loaded.
     * @endcond */
    uint8_t *payload;
} zupt_block_t;

/* Buffer canary for keyring overflow detection */
/**
 * @cond PORT
 * @def ZUPT_CANARY
 * @brief Padrão mágico usado como canary de borda do @ref zupt_keyring_t.
 * @details Escrito no início e no fim do contexto de chaves. Qualquer escrita
 * fora dos limites que toque um dos dois valores é detectada por
 * @ref zupt_keyring_check.
 * @endcond
 * @cond INGLES
 * @def ZUPT_CANARY
 * @brief Magic pattern used as bounds canary of @ref zupt_keyring_t.
 * @details Written at the beginning and at the end of the key context. Any write
 * out of bounds that touches one of the two values is detected by
 * @ref zupt_keyring_check.
 * @endcond */
#define ZUPT_CANARY 0xDEADCAFEBABEFACEULL

/**
 * @cond PORT
 * @struct zupt_keyring_t
 * @brief  Material de chave de sessão: chaves AES e MAC, salt, nonce base e contadores.
 * @details É o estado que @ref zupt_encrypt_buffer e @ref zupt_decrypt_buffer
 * usam para cifrar e autenticar um bloco. Pode vir de senha
 * (@ref zupt_derive_keys) ou de um KEM híbrido
 * (@ref zupt_hybrid_encrypt_init / @ref zupt_hybrid_decrypt_init).
 *
 * As duas palavras `canary_head`/`canary_tail` delimitam o struct e
 * valem @ref ZUPT_CANARY depois de @ref zupt_keyring_init.
 * @note    Contém segredos: não deve ser copiado para memória trocável. Use
 * @ref zupt_mlock_keys para tentar fixá-lo em RAM e
 * @ref zupt_secure_wipe antes de descartá-lo.
 * @endcond
 * @cond INGLES
 * @struct zupt_keyring_t
 * @brief  Session key material: AES and MAC keys, salt, base nonce and counters.
 * @details It is the state that @ref zupt_encrypt_buffer and @ref zupt_decrypt_buffer
 * use to encrypt and authenticate a block. It may come from a password
 * (@ref zupt_derive_keys) or from a hybrid KEM
 * (@ref zupt_hybrid_encrypt_init / @ref zupt_hybrid_decrypt_init).
 *
 * The two words `canary_head`/`canary_tail` bound the struct and
 * hold @ref ZUPT_CANARY after @ref zupt_keyring_init.
 * @note    Contains secrets: it must not be copied to swappable memory. Use
 * @ref zupt_mlock_keys to try to pin it in RAM and
 * @ref zupt_secure_wipe before discarding it.
 * @endcond */
typedef struct {
    /**
     * @cond PORT
     * Canary de inicialização, deve ser igual a ::ZUPT_CANARY.
     * @endcond
     * @cond INGLES
     * Initialization canary, must equal ::ZUPT_CANARY.
     * @endcond */
    uint64_t canary_head;
    /**
     * @cond PORT
     * Chave AES-256-CTR.
     * @endcond
     * @cond INGLES
     * AES-256-CTR key.
     * @endcond */
    uint8_t enc_key[ZUPT_AES_KEY_SIZE];
    /**
     * @cond PORT
     * Chave de 32 bytes para o HMAC-SHA256 da autenticação.
     * @endcond
     * @cond INGLES
     * 32-byte key for the authentication HMAC-SHA256.
     * @endcond */
    uint8_t mac_key[ZUPT_HMAC_SIZE];
    /**
     * @cond PORT
     * Salt de 32 bytes usado no PBKDF2.
     * @endcond
     * @cond INGLES
     * 32-byte salt used in PBKDF2.
     * @endcond */
    uint8_t salt[ZUPT_SALT_SIZE];
    /**
     * @cond PORT
     * Nonce base de 16 bytes combinado com o número do bloco.
     * @endcond
     * @cond INGLES
     * 16-byte base nonce combined with the block number.
     * @endcond */
    uint8_t base_nonce[ZUPT_NONCE_SIZE];
    /**
     * @cond PORT
     * Iterações de PBKDF2 usadas na derivação, registrado no arquivo.
     * @endcond
     * @cond INGLES
     * PBKDF2 iterations used in the derivation, recorded in the file.
     * @endcond */
    uint32_t iterations;
    /**
     * @cond PORT
     * 1 quando a chave está pronta para uso. É posto a 1 pelas
     * funções de geração/importação de chave; nenhum código em
     * `src/` o recoloca a 0.
     * @endcond
     * @cond INGLES
     * 1 when the key is ready for use. It is set to 1 by the
     * key generation/import functions; no code in
     * `src/` sets it back to 0.
     * @endcond */
    int active;
    /**
     * @cond PORT
     * Canary final, deve ser igual a ::ZUPT_CANARY.
     * @endcond
     * @cond INGLES
     * Final canary, must equal ::ZUPT_CANARY.
     * @endcond */
    uint64_t canary_tail;
} zupt_keyring_t;

/* Check keyring canaries — abort on buffer overflow */
/**
 * @cond PORT
 * @brief Monta um anel de chaves vazio, com os dois canary ligados.
 * @details Zera o struct inteiro byte a byte através de um ponteiro
 * `volatile`, para que o compilador não elimine a limpeza, e então
 * escreve @ref ZUPT_CANARY em `canary_head` e `canary_tail`.
 * @param[out] kr Anel de chaves a inicializar.
 * @post `canary_head` e `canary_tail` valem @ref ZUPT_CANARY e todo o restante
 * é zero.
 * @see zupt_keyring_check()
 * @endcond
 * @cond INGLES
 * @brief Builds an empty keyring, with both canaries set.
 * @details It zeroes the whole struct byte by byte through a
 * `volatile` pointer, so the compiler does not eliminate the clearing, and then
 * writes @ref ZUPT_CANARY into `canary_head` and `canary_tail`.
 * @param[out] kr Keyring to initialize.
 * @post `canary_head` and `canary_tail` hold @ref ZUPT_CANARY and everything else
 * is zero.
 * @see zupt_keyring_check()
 * @endcond */
static inline void zupt_keyring_init(zupt_keyring_t *kr) {
    volatile uint8_t *p = (volatile uint8_t *)kr;
    for (size_t i = 0; i < sizeof(*kr); i++) p[i] = 0;
    kr->canary_head = ZUPT_CANARY;
    kr->canary_tail = ZUPT_CANARY;
}
/**
 * @cond PORT
 * @brief Verifica os canary do anel de chaves e termina o processo se foram corrompidos.
 * @details Se `canary_head` ou `canary_tail` divergir de @ref ZUPT_CANARY,
 * imprime uma mensagem em `stderr` e termina o processo imediatamente
 * com status 127. Não retorna ao chamador nesse caso.
 * @param[in] kr Anel de chaves a auditar.
 * @warning Esta função pode encerrar o processo de quem a chamou. O comentário
 * do código diz "Use exit(127)", mas a chamada real é `_exit(127)` —
 * que encerra sem correr `atexit` nem esvaziar `stdio`, de modo que
 * um `fprintf` anterior em `stdout` pode se perder. `_exit` é
 * declarada por `<unistd.h>`, incluído apenas no ramo não-Windows
 * deste cabeçalho (linha 104); o ramo Windows (`<windows.h>` e
 * `<direct.h>`) não inclui cabeçalho que a declare.
 * @see zupt_keyring_init(), ZUPT_CANARY, @ref page-limitacoes
 * @endcond
 * @cond INGLES
 * @brief Checks the keyring canaries and terminates the process if they were corrupted.
 * @details If `canary_head` or `canary_tail` differs from @ref ZUPT_CANARY,
 * it prints a message to `stderr` and terminates the process immediately
 * with status 127. It does not return to the caller in that case.
 * @param[in] kr Keyring to audit.
 * @warning This function may terminate the calling process. The code comment
 * says "Use exit(127)", but the actual call is `_exit(127)` —
 * which terminates without running `atexit` or flushing `stdio`, so
 * a previous `fprintf` to `stdout` may be lost. `_exit` is
 * declared by `<unistd.h>`, included only in the non-Windows branch
 * of this header (line 104); the Windows branch (`<windows.h>` and
 * `<direct.h>`) does not include a header that declares it.
 * @see zupt_keyring_init(), ZUPT_CANARY, @ref page-limitacoes
 * @endcond */
static inline void zupt_keyring_check(const zupt_keyring_t *kr) {
    if (kr->canary_head != ZUPT_CANARY || kr->canary_tail != ZUPT_CANARY) {
        fprintf(stderr, "FATAL: keyring buffer overflow detected (canary corrupted)\n");
        /* Use exit(127) instead of abort() to avoid needing <stdlib.h> */
        _exit(127);
    }
}

/**
 * @cond PORT
 * @struct zupt_filelist_t
 * @brief  Lista dinâmica de pares (caminho em disco, caminho no arquivo).
 * @details Vetor de strings `paths` e `arc_paths` com `count` entradas
 * ocupadas e `capacity` de espaço alocado. Gerado por
 * @ref zupt_collect_files / @ref zupt_filelist_add e liberado por
 * @ref zupt_filelist_free.
 * @endcond
 * @cond INGLES
 * @struct zupt_filelist_t
 * @brief  Dynamic list of pairs (on-disk path, path in the archive).
 * @details Vector of strings `paths` and `arc_paths` with `count` occupied
 * entries and `capacity` of allocated space. Produced by
 * @ref zupt_collect_files / @ref zupt_filelist_add and freed by
 * @ref zupt_filelist_free.
 * @endcond */
typedef struct {
    /**
     * @cond PORT
     * Vetor de caminhos no sistema de arquivos.
     * @endcond
     * @cond INGLES
     * Vector of paths in the file system.
     * @endcond */
    char **paths,
                 /**
                  * @cond PORT
                  * Vetor de caminhos arquivados (relativos), alinhado com paths.
                  * @endcond
                  * @cond INGLES
                  * Vector of archived (relative) paths, aligned with paths.
                  * @endcond */
                 **arc_paths;
    /**
     * @cond PORT
     * Quantidade de itens válidos nos vetores.
     * @endcond
     * @cond INGLES
     * Number of valid items in the vectors.
     * @endcond */
    int count,
                 /**
                  * @cond PORT
                  * Capacidade alocada dos vetores.
                  * @endcond
                  * @cond INGLES
                  * Allocated capacity of the vectors.
                  * @endcond */
                 capacity;
} zupt_filelist_t;

/**
 * @cond PORT
 * @struct zupt_options_t
 * @brief  Parâmetros de uma operação de compressão/extração.
 * @details Uma única estrutura cobre compressão, extração, listagem e teste.
 * Nem todos os campos são lidos por todas as operações (por exemplo
 * `password` só tem efeito na derivação de chave por senha).
 * @note    `password` tem capacidade fixa de 256 bytes, incluindo o
 * terminador nulo: senhas maiores são truncadas pelo chamador, e esse
 * truncamento altera a chave derivada.
 * @endcond
 * @cond INGLES
 * @struct zupt_options_t
 * @brief  Parameters of a compression/extraction operation.
 * @details A single structure covers compression, extraction, listing and testing.
 * Not all fields are read by every operation (for example
 * `password` only takes effect in password-based key derivation).
 * @note    `password` has a fixed capacity of 256 bytes, including the
 * null terminator: larger passwords are truncated by the caller, and that
 * truncation alters the derived key.
 * @endcond */
typedef struct {
    /**
     * @cond PORT
     * Nível de compressão, 1 a 9.
     * @endcond
     * @cond INGLES
     * Compression level, 1 to 9.
     * @endcond */
    int level;
    /**
     * @cond PORT
     * Tamanho de bloco em KB.
     * @endcond
     * @cond INGLES
     * Block size in KB.
     * @endcond */
    uint32_t block_size;
    /**
     * @cond PORT
     * Codec principal, um dos códigos `ZUPT_CODEC_*`.
     * @endcond
     * @cond INGLES
     * Primary codec, one of the `ZUPT_CODEC_*` codes.
     * @endcond */
    uint16_t codec_id;
    /**
     * @cond PORT
     * 1 para saída detalhada; a biblioteca em si não imprime.
     * @endcond
     * @cond INGLES
     * 1 for verbose output; the library itself does not print.
     * @endcond */
    int verbose,
                 /**
                  * @cond PORT
                  * 1 para criptografar o arquivo.
                  * @endcond
                  * @cond INGLES
                  * 1 to encrypt the file.
                  * @endcond */
                 encrypt,
                 /**
                  * @cond PORT
                  * 1 para suprimir mensagens; reservado, sem efeito na biblioteca.
                  * @endcond
                  * @cond INGLES
                  * 1 to suppress messages; reserved, no effect in the library.
                  * @endcond */
                 quiet,
                 /**
                  * @cond PORT
                  * 1 para modo sólido (dicionário compartilhado); reservado.
                  * @endcond
                  * @cond INGLES
                  * 1 for solid mode (shared dictionary); reserved.
                  * @endcond */
                 solid,
                 /**
                  * @cond PORT
                  * Número de threads desejado; reservado, o processamento é sequencial.
                  * @endcond
                  * @cond INGLES
                  * Desired number of threads; reserved, processing is sequential.
                  * @endcond */
                 threads;
    /**
     * @cond PORT
     * 1 para modo híbrido pós-quântico, 0 para PBKDF2 puro.
     * @endcond
     * @cond INGLES
     * 1 for post-quantum hybrid mode, 0 for pure PBKDF2.
     * @endcond */
    int pq_mode;
    /**
     * @cond PORT
     * 1 para habilitar deduplicação em nível de bloco.
     * @endcond
     * @cond INGLES
     * 1 to enable deduplication at block level.
     * @endcond */
    int dedup;
    /**
     * @cond PORT
     * Senha usada para derivar as chaves.
     * @endcond
     * @cond INGLES
     * Password used to derive the keys.
     * @endcond */
    char password[256];
    /**
     * @cond PORT
     * Caminho de arquivo de chaves .zupt-key.
     * @endcond
     * @cond INGLES
     * Path of the .zupt-key key file.
     * @endcond */
    char keyfile[ZUPT_MAX_PATH];
    /**
     * @cond PORT
     * Chaveiro derivado, preenchido por ::zupt_derive_keys().
     * @endcond
     * @cond INGLES
     * Derived keyring, filled by ::zupt_derive_keys().
     * @endcond */
    zupt_keyring_t keyring;
} zupt_options_t;

/* ═══════════════════════════════════════════════════════════════════
 * PORTABLE LITTLE-ENDIAN SERIALIZATION
 *
 * All multi-byte fields in the on-disk format are stored as LE.
 * These helpers ensure correct behaviour on both LE and BE hosts.
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * @cond PORT
 * @brief Grava `v` como 2 bytes little-endian em `p`.
 * @param[out] p Destino de exatamente 2 bytes graváveis.
 * @param[in]  v Valor de 16 bits a serializar.
 * @post `p[0]` contém o byte menos significativo e `p[1]` o mais significativo.
 * @note Não depende da endianidade do host: os bytes são extraídos por
 * deslocamento e máscara.
 * @endcond
 * @cond INGLES
 * @brief Writes `v` as 2 little-endian bytes to `p`.
 * @param[out] p Destination of exactly 2 writable bytes.
 * @param[in]  v 16-bit value to serialize.
 * @post `p[0]` holds the least significant byte and `p[1]` the most significant.
 * @note It does not depend on host endianness: the bytes are extracted by
 * shift and mask.
 * @endcond */
static inline void zupt_le16_put(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
}
/**
 * @cond PORT
 * @brief Grava `v` como 4 bytes little-endian em `p`.
 * @param[out] p Destino de exatamente 4 bytes graváveis.
 * @param[in]  v Valor de 32 bits a serializar.
 * @post `p[0]` é o byte menos significativo, `p[3]` o mais significativo.
 * @endcond
 * @cond INGLES
 * @brief Writes `v` as 4 little-endian bytes to `p`.
 * @param[out] p Destination of exactly 4 writable bytes.
 * @param[in]  v 32-bit value to serialize.
 * @post `p[0]` is the least significant byte, `p[3]` the most significant.
 * @endcond */
static inline void zupt_le32_put(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}
/**
 * @cond PORT
 * @brief Grava `v` como 8 bytes little-endian em `p`.
 * @param[out] p Destino de exatamente 8 bytes graváveis.
 * @param[in]  v Valor de 64 bits a serializar.
 * @post `p[0]` é o byte menos significativo, `p[7]` o mais significativo.
 * @endcond
 * @cond INGLES
 * @brief Writes `v` as 8 little-endian bytes to `p`.
 * @param[out] p Destination of exactly 8 writable bytes.
 * @param[in]  v 64-bit value to serialize.
 * @post `p[0]` is the least significant byte, `p[7]` the most significant.
 * @endcond */
static inline void zupt_le64_put(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) { p[i] = (uint8_t)(v & 0xFF); v >>= 8; }
}
/**
 * @cond PORT
 * @brief Lê 2 bytes little-endian de `p` como `uint16_t`.
 * @param[in] p Leitura de exatamente 2 bytes.
 * @return Valor reconstruído, com `p[0]` como byte menos significativo.
 * @endcond
 * @cond INGLES
 * @brief Reads 2 little-endian bytes from `p` as a `uint16_t`.
 * @param[in] p Read of exactly 2 bytes.
 * @return Reconstructed value, with `p[0]` as the least significant byte.
 * @endcond */
static inline uint16_t zupt_le16_get(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}
/**
 * @cond PORT
 * @brief Lê 4 bytes little-endian de `p` como `uint32_t`.
 * @param[in] p Leitura de exatamente 4 bytes.
 * @return Valor reconstruído, com `p[0]` como byte menos significativo.
 * @endcond
 * @cond INGLES
 * @brief Reads 4 little-endian bytes from `p` as a `uint32_t`.
 * @param[in] p Read of exactly 4 bytes.
 * @return Reconstructed value, with `p[0]` as the least significant byte.
 * @endcond */
static inline uint32_t zupt_le32_get(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
/**
 * @cond PORT
 * @brief Lê 8 bytes little-endian de `p` como `uint64_t`.
 * @param[in] p Leitura de exatamente 8 bytes.
 * @return Valor reconstruído, com `p[0]` como byte menos significativo.
 * @endcond
 * @cond INGLES
 * @brief Reads 8 little-endian bytes from `p` as a `uint64_t`.
 * @param[in] p Read of exactly 8 bytes.
 * @return Reconstructed value, with `p[0]` as the least significant byte.
 * @endcond */
static inline uint64_t zupt_le64_get(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

/* ═══════════════════════════════════════════════════════════════════
 * SECURE MEMORY WIPE (resists dead-store elimination by compilers)
 * ═══════════════════════════════════════════════════════════════════ */

/* FRAMA-C: Secure memory wipe — resists dead-store elimination */
/*@ requires \valid((uint8_t *)ptr + (0..len-1));
  @ assigns ((uint8_t *)ptr)[0..len-1];
  @ ensures \forall integer i; 0 <= i < len ==> ((uint8_t *)ptr)[i] == 0;
*/
/**
 * @cond PORT
 * @brief Zera `len` bytes de `ptr`, tentando impedir que o compilador elimine a escrita.
 * @details O objetivo é apagar material de chave antes de liberar a memória.
 * Uma simples `memset` pode ser otimizada fora do código quando o
 * buffer não é lido depois; as variantes escolhidas impedem isso.
 * Ramais de plataforma:
 * - Windows (`_WIN32`): `SecureZeroMemory`;
 * - glibc 2.25 ou mais nova: `explicit_bzero` (declaração local);
 * - FreeBSD/OpenBSD: `explicit_bzero` (declaração local);
 * - demais plataformas: laço byte a byte através de um ponteiro
 * `volatile uint8_t *`.
 * @param[out] ptr Início da região a zerar.
 * @param[in]  len Número de bytes a zerar.
 * @post Todos os `len` bytes de `ptr` valem 0.
 * @note A portabilidade entre as quatro variantes não é verificada neste
 * repositório: não há compilação/CI para as plataformas não-Linux.
 * @see zupt_mlock_keys()
 * @endcond
 * @cond INGLES
 * @brief Zeroes `len` bytes of `ptr`, trying to prevent the compiler from eliminating the write.
 * @details The goal is to erase key material before freeing the memory.
 * A simple `memset` may be optimized out of the code when the
 * buffer is not read afterwards; the chosen variants prevent this.
 * Platform branches:
 * - Windows (`_WIN32`): `SecureZeroMemory`;
 * - glibc 2.25 or newer: `explicit_bzero` (local declaration);
 * - FreeBSD/OpenBSD: `explicit_bzero` (local declaration);
 * - other platforms: byte-by-byte loop through a
 * `volatile uint8_t *` pointer.
 * @param[out] ptr Start of the region to zero.
 * @param[in]  len Number of bytes to zero.
 * @post All `len` bytes of `ptr` hold 0.
 * @note Portability across the four variants is not verified in this
 * repository: there is no build/CI for non-Linux platforms.
 * @see zupt_mlock_keys()
 * @endcond */
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

/**
 * @cond PORT
 * @brief Determina se `path` aponta para um arquivo regular.
 * @details Usado para pular links simbólicos, dispositivos, FIFOs e sockets
 * durante a coleta de arquivos, evitando ler algo que não é um
 * conteúdo arquivável.
 * Ramais de plataforma:
 * - Windows (`_WIN32`): `GetFileAttributesA` e rejeição de
 * `FILE_ATTRIBUTE_DIRECTORY`, `FILE_ATTRIBUTE_DEVICE` e
 * `FILE_ATTRIBUTE_REPARSE_POINT`;
 * - demais: `lstat` (não segue o link) e `S_ISREG`.
 * @param[in] path Caminho a testar.
 * @return 1 quando o alvo é um arquivo regular; 0 quando não é, ou quando a
 * consulta de atributos/`lstat` falha.
 * @note A consulta não segue links simbólicos em nenhum dos dois ramos, então
 * um link para um arquivo regular devolve 0.
 * @endcond
 * @cond INGLES
 * @brief Determines whether `path` points to a regular file.
 * @details It is used to skip symlinks, devices, FIFOs and sockets
 * during file collection, avoiding reading something that is not an
 * archivable content.
 * Platform branches:
 * - Windows (`_WIN32`): `GetFileAttributesA` and rejection of
 * `FILE_ATTRIBUTE_DIRECTORY`, `FILE_ATTRIBUTE_DEVICE` and
 * `FILE_ATTRIBUTE_REPARSE_POINT`;
 * - others: `lstat` (does not follow the link) and `S_ISREG`.
 * @param[in] path Path to test.
 * @return 1 when the target is a regular file; 0 when it is not, or when the
 * attribute/`lstat` query fails.
 * @note The query does not follow symlinks in either branch, so
 * a link to a regular file returns 0.
 * @endcond */
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
/**
 * @cond PORT
 * @brief Comprime vários arquivos em um arquivo único em modo sólido.
 * @details No modo sólido os blocos dos diversos arquivos compartilham o mesmo
 * contexto do codec, o que costuma reduzir o tamanho quando há
 * arquivos parecidos entre si. Em contrapartida os blocos deixam de
 * ser independentes: extrair um item exige reproduzir a decompressão
 * dos anteriores.
 * @param[in]     out  Caminho do arquivo de saída a criar.
 * @param[in]     arc  Vetor de `n` caminhos lógicos (como ficam gravados).
 * @param[in]     disk Vetor de `n` caminhos reais em disco.
 * @param[in]     n    Número de pares; `arc` e `disk` devem ter `n` elementos.
 * @param[in,out] opts Opções; o campo `keyring` é montado quando há cifra.
 * @return @ref ZUPT_OK em sucesso; código negativo em falha.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho
 * mas não possui definição em `src/`.
 * @see ZUPT_FLAG_SOLID, zupt_compress_files()
 * @endcond
 * @cond INGLES
 * @brief Compresses several files into a single file in solid mode.
 * @details In solid mode the blocks of the various files share the same
 * codec context, which usually reduces the size when there
 * are similar files among each other. In return the blocks stop being
 * independent: extracting an item requires replaying the decompression
 * of the previous ones.
 * @param[in]     out  Path of the output file to create.
 * @param[in]     arc  Vector of `n` logical paths (as they will be stored).
 * @param[in]     disk Vector of `n` actual paths on disk.
 * @param[in]     n    Number of pairs; `arc` and `disk` must have `n` elements.
 * @param[in,out] opts Options; the `keyring` field is assembled when a cipher is used.
 * @return @ref ZUPT_OK on success; negative code on failure.
 * @note In this revision of the repository, the symbol is declared in this header
 * but has no definition in `src/`.
 * @see ZUPT_FLAG_SOLID, zupt_compress_files()
 * @endcond */
zupt_error_t zupt_compress_solid(const char *out, const char **arc, const char **disk, int n, zupt_options_t *opts);

/* ─── SHA-256 ─── */
/**
 * @cond PORT
 * @struct zupt_sha256_ctx
 * @brief  Estado incremental de uma computação SHA-256.
 * @details `state` guarda as 8 palavras de 32 bits do estado de trabalho;
 * `count` acumula o total de bytes absorvidos; `buf` guarda os bytes
 * ainda não processados do bloco corrente. Usado na sequência
 * @ref zupt_sha256_init → @ref zupt_sha256_update →
 * @ref zupt_sha256_final. Implementado em src/zupt_sha256.c.
 * @endcond
 * @cond INGLES
 * @struct zupt_sha256_ctx
 * @brief  Incremental state of a SHA-256 computation.
 * @details `state` holds the 8 32-bit words of the working state;
 * `count` accumulates the total number of bytes absorbed; `buf` holds the bytes
 * of the current block not yet processed. Used in the sequence
 * @ref zupt_sha256_init → @ref zupt_sha256_update →
 * @ref zupt_sha256_final. Implemented in src/zupt_sha256.c.
 * @endcond */
typedef struct {
    /**
     * @cond PORT
     * Vetor de estado SHA-256, oito palavras de 32 bits (H0..H7).
     * @endcond
     * @cond INGLES
     * SHA-256 state vector, eight 32-bit words (H0..H7).
     * @endcond */
    uint32_t state[8];
    /**
     * @cond PORT
     * Quantidade total de bytes processados.
     * @endcond
     * @cond INGLES
     * Total number of bytes processed.
     * @endcond */
    uint64_t count;
    /**
     * @cond PORT
     * Buffer parcial de até 64 bytes, um bloco do SHA-256.
     * @endcond
     * @cond INGLES
     * Partial buffer of up to 64 bytes, one SHA-256 block.
     * @endcond */
    uint8_t buf[64];
} zupt_sha256_ctx;
/**
 * @cond PORT
 * @brief Prepara o contexto para computar um novo digest SHA-256.
 * @param[out] c Contexto a inicializar.
 * @post O estado de trabalho recebe o vetor inicial do SHA-256, `count` vale 0
 * e o buffer de bloco corrente é zerado.
 * @endcond
 * @cond INGLES
 * @brief Prepares the context to compute a new SHA-256 digest.
 * @param[out] c Context to initialize.
 * @post The working state receives the SHA-256 initial vector, `count` holds 0
 * and the current block buffer is zeroed.
 * @endcond */
void zupt_sha256_init(zupt_sha256_ctx *c);
/**
 * @cond PORT
 * @brief Absorve mais `n` bytes na computação incremental do digest.
 * @param[in,out] c Contexto já inicializado.
 * @param[in]     d Bytes a absorver (pode ser NULL apenas se `n` for 0).
 * @param[in]     n Número de bytes a processar.
 * @note Blocos completos de 64 bytes são comprimidos imediatamente; a parte
 * restante fica retida em `c->buf`.
 * @endcond
 * @cond INGLES
 * @brief Absorbs `n` more bytes into the incremental digest computation.
 * @param[in,out] c Context already initialized.
 * @param[in]     d Bytes to absorb (may be NULL only if `n` is 0).
 * @param[in]     n Number of bytes to process.
 * @note Full 64-byte blocks are compressed immediately; the remaining
 * part is kept in `c->buf`.
 * @endcond */
void zupt_sha256_update(zupt_sha256_ctx *c, const uint8_t *d, size_t n);
/**
 * @cond PORT
 * @brief Aplica o padding, comprime o último bloco e produz o digest final.
 * @param[in,out] c Contexto a finalizar.
 * @param[out]    h Destino de exatamente 32 bytes do digest.
 * @note Depois desta chamada o contexto não deve ser reutilizado sem nova
 * @ref zupt_sha256_init.
 * @endcond
 * @cond INGLES
 * @brief Applies the padding, compresses the last block and produces the final digest.
 * @param[in,out] c Context to finalize.
 * @param[out]    h Destination of exactly 32 bytes of the digest.
 * @note After this call the context must not be reused without a new
 * @ref zupt_sha256_init.
 * @endcond */
void zupt_sha256_final(zupt_sha256_ctx *c, uint8_t h[32]);
/**
 * @cond PORT
 * @brief Calcula o digest SHA-256 de `n` bytes em uma única chamada.
 * @param[in]  d Dados a resumir.
 * @param[in]  n Número de bytes.
 * @param[out] h Destino de exatamente 32 bytes do digest.
 * @see zupt_sha256_init(), zupt_sha256_update(), zupt_sha256_final()
 * @endcond
 * @cond INGLES
 * @brief Computes the SHA-256 digest of `n` bytes in a single call.
 * @param[in]  d Data to hash.
 * @param[in]  n Number of bytes.
 * @param[out] h Destination of exactly 32 bytes of the digest.
 * @see zupt_sha256_init(), zupt_sha256_update(), zupt_sha256_final()
 * @endcond */
void zupt_sha256(const uint8_t *d, size_t n, uint8_t h[32]);

/* ─── AES-256 ─── */
/**
 * @cond PORT
 * @struct zupt_aes256_ctx
 * @brief  Round keys expandidas para AES-256.
 * @details `rk` contém as 60 palavras de 32 bits do expandimento de chave do
 * AES-256 (15 rodadas × 4 palavras, cobrindo 14 rodadas). A
 * expansão é feita por @ref zupt_aes256_init.
 * @note Só existe expansão para cifrar: a biblioteca usa o AES apenas no modo
 * CTR (@ref zupt_aes256_ctr), que requer somente a primitiva de
 * cifra de bloco. Não há expansão para decifrar.
 * @see src/zupt_aes256.c
 * @endcond
 * @cond INGLES
 * @struct zupt_aes256_ctx
 * @brief  Expanded round keys for AES-256.
 * @details `rk` holds the 60 32-bit words of the AES-256 key
 * expansion (15 rounds × 4 words, covering 14 rounds). The
 * expansion is performed by @ref zupt_aes256_init.
 * @note Only an encryption expansion exists: the library uses AES only in CTR
 * mode (@ref zupt_aes256_ctr), which requires only the block
 * cipher primitive. There is no decryption expansion.
 * @see src/zupt_aes256.c
 * @endcond */
typedef struct {
    /**
     * @cond PORT
     * Rodadas de chave: 15 chaves de rodada de 4 colunas de 32 bits, com espaço de sobra.
     * @endcond
     * @cond INGLES
     * Round keys: 15 round keys of 4 32-bit columns, with spare space.
     * @endcond */
    uint32_t rk[60];
} zupt_aes256_ctx;
/**
 * @cond PORT
 * @brief Expande uma chave de 32 bytes para as 60 round keys do AES-256.
 * @details As 8 palavras iniciais são montadas a partir dos bytes da chave na
 * ordem mais-significativo-primeiro dentro de cada palavra. As demais
 * são geradas pela recursão do AES-256, aplicando S-box + RCON a cada
 * 8 palavras e S-box adicional na posição `i % 8 == 4`.
 * @param[out] c   Contexto que recebe as round keys (`rk[0..59]` é escrito).
 * @param[in]  key Chave de 32 bytes legíveis.
 * @post `c->rk[0..59]` fica inicializado e é derivado apenas de `key`.
 * @see zupt_aes256_encrypt_block, zupt_aes256_ctr
 * @endcond
 * @cond INGLES
 * @brief Expands a 32-byte key into the 60 round keys of AES-256.
 * @details The first 8 words are assembled from the key bytes in
 * most-significant-first order within each word. The remaining ones
 * are generated by the AES-256 recursion, applying S-box + RCON every
 * 8 words and an additional S-box at position `i % 8 == 4`.
 * @param[out] c   Context that receives the round keys (`rk[0..59]` is written).
 * @param[in]  key Readable 32-byte key.
 * @post `c->rk[0..59]` is initialized and derived only from `key`.
 * @see zupt_aes256_encrypt_block, zupt_aes256_ctr
 * @endcond */
void zupt_aes256_init(zupt_aes256_ctx *c, const uint8_t key[32]);
/**
 * @cond PORT
 * @brief Cifra um único bloco de 16 bytes com as round keys já expandidas.
 * @details É a primitiva ECB de um bloco: não há encadeamento, contador ou IV
 * aqui. Serve de motor para @ref zupt_aes256_ctr.
 * Duas implementações coexistem e a escolha é feita em tempo de
 * execução: quando compilado para x86/x86-64 com GCC/Clang e sem
 * `ZUPT_FORCE_PORTABLE_AES`, e `__builtin_cpu_supports("aes")` é
 * verdadeiro, usa-se AES-NI; nos demais casos o caminho portátil em C.
 * @param[in]  c   Round keys de @ref zupt_aes256_init.
 * @param[in]  in  Bloco de entrada, 16 bytes legíveis.
 * @param[out] out Bloco cifrado, 16 bytes graváveis.
 * @pre `in` e `out` devem ser disjuntos, conforme a cláusula `\separated` da
 * anotação ACSL adjunta.
 * @post Os 16 bytes de `out` ficam inicializados.
 * @endcond
 * @cond INGLES
 * @brief Encrypts a single 16-byte block with the already expanded round keys.
 * @details It is the single-block ECB primitive: there is no chaining, counter or IV
 * here. It serves as the engine for @ref zupt_aes256_ctr.
 * Two implementations coexist and the choice is made at run
 * time: when compiled for x86/x86-64 with GCC/Clang and without
 * `ZUPT_FORCE_PORTABLE_AES`, and `__builtin_cpu_supports("aes")` is
 * true, AES-NI is used; otherwise the portable C path.
 * @param[in]  c   Round keys from @ref zupt_aes256_init.
 * @param[in]  in  Input block, 16 readable bytes.
 * @param[out] out Encrypted block, 16 writable bytes.
 * @pre `in` and `out` must be disjoint, as per the `\separated` clause of the
 * adjunct ACSL annotation.
 * @post The 16 bytes of `out` are initialized.
 * @endcond */
void zupt_aes256_encrypt_block(const zupt_aes256_ctx *c, const uint8_t in[16], uint8_t out[16]);

/* ─── Crypto ops ─── */
/**
 * @cond PORT
 * @name Operações criptográficas de alto nível
 *
 * @{
 * @endcond
 * @cond INGLES
 * @name High-level cryptographic operations
 *
 * @{
 * @endcond */

/**
 * @cond PORT
 * @brief  Calcula HMAC-SHA256 (RFC 2104).
 * @param[in]  key  Chave do MAC, de `klen` bytes legíveis.
 * @param[in]  klen Comprimento da chave, em bytes; acima de 64 a chave é
 * pré-hashed com SHA-256 antes de montar os pads.
 * @param[in]  data Mensagem autenticada, de `dlen` bytes legíveis.
 * @param[in]  dlen Comprimento da mensagem, em bytes.
 * @param[out] mac  Destino de exatamente 32 bytes do MAC.
 * @post Os 32 bytes de `mac` ficam inicializados.
 * @note Implementada em `src/zupt_crypto.c`, que detalha a montagem dos pads
 * e a limpeza dos temporários.
 * @see zupt_sha256, zupt_pbkdf2_sha256, zupt_encrypt_buffer
 * @endcond
 * @cond INGLES
 * @brief  Computes HMAC-SHA256 (RFC 2104).
 * @param[in]  key  MAC key, `klen` readable bytes.
 * @param[in]  klen Key length, in bytes; above 64 the key is
 * pre-hashed with SHA-256 before the pads are built.
 * @param[in]  data Authenticated message, `dlen` readable bytes.
 * @param[in]  dlen Message length, in bytes.
 * @param[out] mac  Destination of exactly 32 bytes of the MAC.
 * @post The 32 bytes of `mac` are initialized.
 * @note Implemented in `src/zupt_crypto.c`, which details the pad construction
 * and the clearing of temporaries.
 * @see zupt_sha256, zupt_pbkdf2_sha256, zupt_encrypt_buffer
 * @endcond */
void zupt_hmac_sha256(const uint8_t *key, size_t klen, const uint8_t *data, size_t dlen, uint8_t mac[32]);

/**
 * @cond PORT
 * @brief  Deriva chave a partir de senha com PBKDF2-HMAC-SHA256 (RFC 2898).
 * @param[in]  pw     Senha (bytes da senha em claro).
 * @param[in]  pwlen  Comprimento da senha, em bytes.
 * @param[in]  salt   Salt, de `slen` bytes legíveis.
 * @param[in]  slen   Comprimento do salt, em bytes.
 * @param[in]  iterations Número de iterações (mínimo 1).
 * @param[out] output     Saída da derivação, `olen` bytes graváveis.
 * @param[in]  olen   Tamanho desejado da chave derivada, em bytes.
 * @note `src/zupt_crypto.c` limita o salt efetivo a 252 bytes por causa de um
 * buffer em pilha; o uso da biblioteca sempre passa
 * @ref ZUPT_SALT_SIZE (32), então o limite é uma rede de segurança.
 * @see ZUPT_KDF_ITERATIONS, zupt_derive_keys
 * @endcond
 * @cond INGLES
 * @brief  Derives a key from a password with PBKDF2-HMAC-SHA256 (RFC 2898).
 * @param[in]  pw     Password (plaintext password bytes).
 * @param[in]  pwlen  Password length, in bytes.
 * @param[in]  salt   Salt, `slen` readable bytes.
 * @param[in]  slen   Salt length, in bytes.
 * @param[in]  iterations Number of iterations (minimum 1).
 * @param[out] output     Derivation output, `olen` writable bytes.
 * @param[in]  olen   Desired size of the derived key, in bytes.
 * @note `src/zupt_crypto.c` limits the effective salt to 252 bytes because of a
 * stack buffer; the library's use always passes
 * @ref ZUPT_SALT_SIZE (32), so the limit is a safety net.
 * @see ZUPT_KDF_ITERATIONS, zupt_derive_keys
 * @endcond */
void zupt_pbkdf2_sha256(const uint8_t *pw, size_t pwlen, const uint8_t *salt, size_t slen, uint32_t iter, uint8_t *out, size_t olen);

/**
 * @cond PORT
 * @brief  Cifra (ou decifra) `len` bytes em modo AES-256-CTR.
 * @details CTR gera keystream cifrando um contador; a mesma função serve para
 * cifrar e decifrar. O contador inicial é uma cópia dos 16 bytes de
 * `nonce` e é incrementado em big-endian apenas nos bytes 8..15.
 * @param[in]  key   Chave AES-256 (32 bytes legíveis).
 * @param[in]  nonce Bloco de contagem inicial (16 bytes legíveis); deve ser
 * único por par (chave, fluxo).
 * @param[in]  in    Dados de entrada, `len` bytes legíveis.
 * @param[out] out   Dados de saída, `len` bytes graváveis.
 * @param[in]  len   Comprimento dos dados, em bytes.
 * @pre `in` e `out` são disjuntos (cláusula `\separated` da anotação ACSL):
 * cifra em lugar não está no contrato.
 * @note Sob `-DZUPT_USE_JASMIN` existe um dispatch adicional em tempo de
 * execução para as primitivas assembly, condicionado a `zupt_cpu`
 * (declarado em `include/zupt_cpuid.h`). Ver `src/zupt_crypto.c`.
 * @see zupt_aes256_init, zupt_aes256_encrypt_block, zupt_encrypt_buffer
 * @endcond
 * @cond INGLES
 * @brief  Encrypts (or decrypts) `len` bytes in AES-256-CTR mode.
 * @details CTR generates a keystream by encrypting a counter; the same function
 * serves to encrypt and to decrypt. The initial counter is a copy of the 16
 * `nonce` bytes and is incremented in big-endian only in bytes 8..15.
 * @param[in]  key   AES-256 key (32 readable bytes).
 * @param[in]  nonce Initial counter block (16 readable bytes); it must be
 * unique per (key, stream) pair.
 * @param[in]  in    Input data, `len` readable bytes.
 * @param[out] out   Output data, `len` writable bytes.
 * @param[in]  len   Length of the data, in bytes.
 * @pre `in` and `out` are disjoint (`\separated` clause of the ACSL annotation):
 * in-place encryption is not part of the contract.
 * @note Under `-DZUPT_USE_JASMIN` there is an additional run-time
 * dispatch to the assembly primitives, conditioned on `zupt_cpu`
 * (declared in `include/zupt_cpuid.h`). See `src/zupt_crypto.c`.
 * @see zupt_aes256_init, zupt_aes256_encrypt_block, zupt_encrypt_buffer
 * @endcond */
void zupt_aes256_ctr(const uint8_t key[32], const uint8_t nonce[16], const uint8_t *in, uint8_t *out, size_t len);

/**
 * @cond PORT
 * @brief  Monta um anel de chaves a partir de senha, salt e nonce base.
 * @details Deriva 64 bytes com @ref zupt_pbkdf2_sha256 sobre a senha (comprida
 * por `strlen`), o salt e `iterations`, e divide o material resultante
 * em `enc_key` (bytes 0..31) e `mac_key` (bytes 32..63). Copia `salt`
 * e `nonce` para o anel, grava `iterations` e liga `active`.
 * O material intermediário em pilha é limpo com @ref zupt_secure_wipe
 * e as duas chaves são passadas a @ref zupt_mlock_keys.
 * @param[out] kr   Anel de chaves a montar.
 * @param[in]  pw   Senha de derivação, terminada em nulo; o comprimento usado é
 * o de `strlen(pw)`.
 * @param[in]  salt Salt de 32 bytes legíveis (deve coincidir com o gravado no
 * cabeçalho de cifra).
 * @param[in]  nonce Nonce base de 16 bytes legíveis.
 * @param[in]  iterations Número de iterações de PBKDF2 a usar (ver
 * @ref ZUPT_KDF_ITERATIONS).
 * @post `kr->active` vale 1 e os campos de chave, salt, nonce e iterações estão
 * preenchidos.
 * @warning Senha maior que a capacidade de @ref zupt_options_t (campo `password`) é
 * truncada pelo chamador antes desta chamada, o que muda a chave.
 * @note Os canários são reescritos por esta função, de modo que ela não
 * detecta uma corrupção anterior do anel.
 * @see ZUPT_ENC_PBKDF2, zupt_keyring_init, zupt_secure_wipe
 * @endcond
 * @cond INGLES
 * @brief  Builds a keyring from password, salt and base nonce.
 * @details It derives 64 bytes with @ref zupt_pbkdf2_sha256 over the password (measured
 * by `strlen`), the salt and `iterations`, and splits the resulting material
 * into `enc_key` (bytes 0..31) and `mac_key` (bytes 32..63). It copies `salt`
 * and `nonce` into the ring, stores `iterations` and sets `active`.
 * The intermediate stack material is cleared with @ref zupt_secure_wipe
 * and the two keys are passed to @ref zupt_mlock_keys.
 * @param[out] kr   Keyring to build.
 * @param[in]  pw   Derivation password, null-terminated; the length used is
 * that of `strlen(pw)`.
 * @param[in]  salt Readable 32-byte salt (must match the one stored in the
 * cipher header).
 * @param[in]  nonce Readable 16-byte base nonce.
 * @param[in]  iterations Number of PBKDF2 iterations to use (see
 * @ref ZUPT_KDF_ITERATIONS).
 * @post `kr->active` holds 1 and the key, salt, nonce and iterations fields are
 * filled.
 * @warning A password larger than the capacity of @ref zupt_options_t (field `password`) is
 * truncated by the caller before this call, which changes the key.
 * @note The canaries are rewritten by this function, so it does not
 * detect a previous corruption of the ring.
 * @see ZUPT_ENC_PBKDF2, zupt_keyring_init, zupt_secure_wipe
 * @endcond */
void zupt_derive_keys(zupt_keyring_t *kr, const char *pw, const uint8_t salt[32], const uint8_t nonce[16], uint32_t iter);

/**
 * @cond PORT
 * @brief  Cifra um payload e produz o envelope Encrypt-then-MAC.
 * @details Formato do envelope devolvido, que é o que vai ao disco:
 * `[16 bytes de nonce do bloco][plen bytes de texto cifrado]
 * [32 bytes de HMAC-SHA256]`. O nonce do bloco é o
 * @ref zupt_keyring_t (campo `base_nonce`) com seus 8 bytes menos
 * significativos XOR `seq` em little-endian; o HMAC, com
 * `mac_key`, cobre `nonce || texto cifrado`.
 * @param[in]  kr   Anel de chaves ativo (`enc_key`, `mac_key` e `base_nonce`
 * válidos; o contrato ACSL exige `active == 1`).
 * @param[in]  plain Dados em claro, `plen` bytes legíveis.
 * @param[in]  plen Comprimento dos dados em claro, em bytes; `plen == 0` gera
 * um envelope de 48 bytes.
 * @param[in]  block_seq Sequência do bloco, que diferencia o nonce entre blocos do
 * mesmo arquivo. Não repita o par (chave, `seq`): a keystream
 * seria reaproveitada.
 * @param[out] olen Recebe o tamanho total do envelope, igual a
 * `16 + plen + 32`.
 * @return Buffer recém-alocado com o envelope, ou `NULL` se a alocação falhar.
 * @retval !=NULL Pacote de `*olen` bytes; o chamador é dono da memória.
 * @retval NULL   Falha de alocação; neste caso `*olen` já foi escrita.
 * @note Quem recebe o buffer é responsável por liberá-lo.
 * @see zupt_decrypt_buffer, ZUPT_BFLAG_ENCRYPTED, zupt_aes256_ctr
 * @endcond
 * @cond INGLES
 * @brief  Encrypts a payload and produces the Encrypt-then-MAC envelope.
 * @details Format of the returned envelope, which is what goes to disk:
 * `[16-byte block nonce][plen bytes of ciphertext]
 * [32 bytes of HMAC-SHA256]`. The block nonce is the
 * @ref zupt_keyring_t (field `base_nonce`) with its 8 least
 * significant bytes XOR `seq` in little-endian; the HMAC, using
 * `mac_key`, covers `nonce || ciphertext`.
 * @param[in]  kr   Active keyring (`enc_key`, `mac_key` and `base_nonce`
 * valid; the ACSL contract requires `active == 1`).
 * @param[in]  plain Plaintext data, `plen` readable bytes.
 * @param[in]  plen Length of the plaintext, in bytes; `plen == 0` produces
 * a 48-byte envelope.
 * @param[in]  block_seq Sequence of the block, which differentiates the nonce across blocks of the
 * same file. Do not repeat the (key, `seq`) pair: the keystream
 * would be reused.
 * @param[out] olen Receives the total size of the envelope, equal to
 * `16 + plen + 32`.
 * @return Newly allocated buffer with the envelope, or `NULL` if the allocation fails.
 * @retval !=NULL Packet of `*olen` bytes; the caller owns the memory.
 * @retval NULL   Allocation failure; in this case `*olen` has already been written.
 * @note Whoever receives the buffer is responsible for freeing it.
 * @see zupt_decrypt_buffer, ZUPT_BFLAG_ENCRYPTED, zupt_aes256_ctr
 * @endcond */
uint8_t *zupt_encrypt_buffer(const zupt_keyring_t *kr, const uint8_t *plain, size_t plen, uint64_t seq, size_t *olen);

/**
 * @cond PORT
 * @brief  Confere o MAC e decifra um envelope produzido por @ref
 * zupt_encrypt_buffer.
 * @details Opera sobre o envelope `[nonce][texto cifrado][HMAC]`: o HMAC é
 * recomputado com `mac_key` e comparado, o nonce do envelope é
 * conferido contra o esperado para `seq`, e só então o texto cifrado
 * é decifrado para um buffer recém-alocado.
 * @param[in]  kr      Anel de chaves ativo.
 * @param[in]  pkg     Envelope, `pkglen` bytes legíveis.
 * @param[in]  pkglen  Comprimento do envelope, em bytes.
 * @param[in]  block_seq Sequência do bloco, a mesma usada na cifra; participa da
 * conferência do nonce.
 * @param[out] olen    Recebe o comprimento dos dados em claro.
 * @return Buffer recém-alocado com os dados em claro, ou `NULL` quando o MAC
 * não valida, o nonce não confere, `pkglen` é inconsistente ou a
 * alocação falha.
 * @note Um retorno `NULL` agrupa causas distintas (autenticação, formato e
 * memória); não há como distingui-las por esta interface.
 * @see zupt_encrypt_buffer, ZUPT_ERR_AUTH_FAIL
 * @endcond
 * @cond INGLES
 * @brief  Checks the MAC and decrypts an envelope produced by @ref
 * zupt_encrypt_buffer.
 * @details It operates over the envelope `[nonce][ciphertext][HMAC]`: the HMAC is
 * recomputed with `mac_key` and compared, the envelope's nonce is
 * checked against the one expected for `seq`, and only then the encrypted text
 * is decrypted into a newly allocated buffer.
 * @param[in]  kr      Active keyring.
 * @param[in]  pkg     Envelope, `pkglen` readable bytes.
 * @param[in]  pkglen  Length of the envelope, in bytes.
 * @param[in]  block_seq Sequence of the block, the same one used in encryption; it takes part in
 * the nonce check.
 * @param[out] olen    Receives the length of the plaintext data.
 * @return Newly allocated buffer with the plaintext data, or `NULL` when the MAC
 * does not validate, the nonce does not match, `pkglen` is inconsistent or the
 * allocation fails.
 * @note A `NULL` return groups distinct causes (authentication, format and
 * memory); there is no way to tell them apart through this interface.
 * @see zupt_encrypt_buffer, ZUPT_ERR_AUTH_FAIL
 * @endcond */
uint8_t *zupt_decrypt_buffer(const zupt_keyring_t *kr, const uint8_t *pkg, size_t pkglen, uint64_t seq, size_t *olen);

/**
 * @cond PORT
 * @brief  Preenche `buf` com bytes de fonte aleatória criptograficamente segura.
 * @details Ramais de plataforma (em `src/zupt_crypto.c`):
 * - Windows (`_WIN32`): `RtlGenRandom` (`SystemFunction036`) carregado
 * via `LoadLibraryA`;
 * - Linux: tenta `getrandom(2)` quando `SYS_getrandom` existe;
 * - demais sistemas / reserva: leitura de `/dev/urandom`.
 * @param[out] buf Destino de `len` bytes graváveis.
 * @param[in]  len Quantidade de bytes a gerar.
 * @warning A função <b>não</b> devolve erro: quando nenhuma fonte está
 * disponível, imprime mensagem fatal em `stderr` e encerra o processo
 * com `exit(1)`. Não há tratamento de erro recuperável.
 * @see zupt_derive_keys, zupt_hybrid_keygen
 * @endcond
 * @cond INGLES
 * @brief  Fills `buf` with bytes from a cryptographically secure random source.
 * @details Platform branches (in `src/zupt_crypto.c`):
 * - Windows (`_WIN32`): `RtlGenRandom` (`SystemFunction036`) loaded
 * via `LoadLibraryA`;
 * - Linux: tries `getrandom(2)` when `SYS_getrandom` exists;
 * - other systems / fallback: reading from `/dev/urandom`.
 * @param[out] buf Destination of `len` writable bytes.
 * @param[in]  len Number of bytes to generate.
 * @warning The function <b>does not</b> return an error: when no source is
 * available, it prints a fatal message to `stderr` and terminates the process
 * with `exit(1)`. There is no recoverable error handling.
 * @see zupt_derive_keys, zupt_hybrid_keygen
 * @endcond */
void zupt_random_bytes(uint8_t *buf, size_t len);

/**
 * @cond PORT
 * @}
 * @endcond
 * @cond INGLES
 * @}
 * @endcond */

/* ─── Memory locking for key material ─── */
/**
 * @cond PORT
 * @brief  Tenta fixar em RAM um intervalo que contém material de chave.
 * @details Objetivo é evitar que segredos sejam escritos em swap. `src/zupt_mlock.c`
 * traz três implementações selecionadas por compilação: POSIX
 * (`mlock`), Windows (`VirtualLock`) e um caminho sem suporte, que é
 * no-op e reporta falha.
 * @param[in] ptr Início do intervalo.
 * @param[in] len Tamanho do intervalo, em bytes.
 * @return 0 quando o bloqueio foi aceito pelo SO; -1 quando não suportado ou
 * recusado (por exemplo limite de `RLIMIT_MEMLOCK`).
 * @note Sucesso depende do SO e do limite de memória bloqueável do processo:
 * um retorno 0 não é garantia de que a região nunca saia da RAM.
 * @see zupt_munlock_keys, zupt_secure_wipe
 * @endcond
 * @cond INGLES
 * @brief  Attempts to pin in RAM an interval that contains key material.
 * @details The goal is to prevent secrets from being written to swap. `src/zupt_mlock.c`
 * provides three implementations selected at compile time: POSIX
 * (`mlock`), Windows (`VirtualLock`) and an unsupported path, which is
 * a no-op and reports failure.
 * @param[in] ptr Start of the interval.
 * @param[in] len Size of the interval, in bytes.
 * @return 0 when the lock was accepted by the OS; -1 when unsupported or
 * refused (for example the `RLIMIT_MEMLOCK` limit).
 * @note Success depends on the OS and on the process's lockable memory limit:
 * a return value of 0 is no guarantee that the region will never leave RAM.
 * @see zupt_munlock_keys, zupt_secure_wipe
 * @endcond */
int  zupt_mlock_keys(void *ptr, size_t len);
/**
 * @cond PORT
 * @brief  Desfaz o bloqueio de RAM feito por @ref zupt_mlock_keys.
 * @param[in] ptr Início do intervalo, como foi passado a @ref zupt_mlock_keys.
 * @param[in] len Tamanho do intervalo, em bytes.
 * @note Não limpa o conteúdo: chame @ref zupt_secure_wipe antes.
 * @endcond
 * @cond INGLES
 * @brief  Undoes the RAM lock made by @ref zupt_mlock_keys.
 * @param[in] ptr Start of the interval, as it was passed to @ref zupt_mlock_keys.
 * @param[in] len Size of the interval, in bytes.
 * @note It does not clear the content: call @ref zupt_secure_wipe first.
 * @endcond */
void zupt_munlock_keys(void *ptr, size_t len);

/* ─── Adaptive compression: file type detection ─── */
/* Returns: -1=store (incompressible), 0=default, 5=medium, 9=max */
/**
 * @cond PORT
 * @brief  Sugere um nível de compressão a partir do cabeçalho do arquivo.
 * @details Heurística de "compressão adaptativa": examina os primeiros bytes de
 * um arquivo para decidir se vale a pena comprimir e com que esforço.
 * A semântica do valor devolvido está indicada no comentário do
 * cabeçalho:
 * - `-1` = armazenar sem compressão (conteúdo já comprimido/incompressível);
 * - `0`  = usar o nível padrão;
 * - `5`  = nível médio;
 * - `9`  = nível máximo.
 * @param[in] header       Primeiros bytes do arquivo.
 * @param[in] header_len   Quantidade de bytes disponíveis em `header`.
 * @return Um dos valores acima; `header_len` pequeno tende a devolver o padrão.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas
 * não possui definição em `src/`.
 * @see ZUPT_CODEC_STORE, zupt_options_t::level
 * @endcond
 * @cond INGLES
 * @brief  Suggests a compression level from the file's header.
 * @details "Adaptive compression" heuristic: it examines the first bytes of
 * a file to decide whether compressing is worthwhile and with how much
 * effort. The semantics of the returned value are given in the header
 * comment:
 * - `-1` = store without compression (content already compressed/incompressible);
 * - `0`  = use the default level;
 * - `5`  = medium level;
 * - `9`  = maximum level.
 * @param[in] header       First bytes of the file.
 * @param[in] header_len   Number of bytes available in `header`.
 * @return One of the values above; a small `header_len` tends to return the default.
 * @note In this revision of the repository, the symbol is declared in this header but
 * has no definition in `src/`.
 * @see ZUPT_CODEC_STORE, zupt_options_t::level
 * @endcond */
int zupt_detect_filetype(const uint8_t *header, size_t header_len);

/* ─── XXH64 ─── */
uint64_t zupt_xxh64(const void *data, size_t len, uint64_t seed);

/* ─── LZ ─── */
/**
 * @cond PORT
 * @brief Compressão do codec LZ de janela fixa.
 *
 * É o codec interno simples do projeto, indicado por `ZUPT_CODEC_STORE`/`ZUPT_CODEC_LZ` nas
 * escolhas automáticas. O formato concreto do bloco comprimido não pode ser descrito nesta revisão
 * por ausência de implementação e de testes em `tests/`.
 * @param[in] src dados de entrada.
 * @param[in] slen tamanho da entrada, em bytes.
 * @param[out] dst buffer de destino.
 * @param[in] dcap capacidade do buffer de destino, em bytes.
 * @param[in] level nível de compressão.
 * @return Tamanho do resultado escrito em `dst`; a convenção de erro não é afirmável nesta revisão.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Fixed-window LZ codec compression.
 *
 * It is the project's simple internal codec, indicated by `ZUPT_CODEC_STORE`/`ZUPT_CODEC_LZ` in
 * automatic codec selection. The concrete format of the compressed block cannot be described in this
 * revision due to the lack of an implementation and of tests in `tests/`.
 * @param[in] src Input data.
 * @param[in] slen Input length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] dcap Destination buffer capacity, in bytes.
 * @param[in] level Compression level.
 * @return Size of the result written to `dst`; the error convention cannot be stated in this revision.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
size_t zupt_lz_compress(const uint8_t *src, size_t slen, uint8_t *dst, size_t dcap, int level);
/**
 * @cond PORT
 * @brief Descompressão do formato produzido por `zupt_lz_compress`.
 * @param[in] src dados comprimidos.
 * @param[in] slen tamanho da entrada comprimida, em bytes.
 * @param[out] dst buffer de destino.
 * @param[in] dlen tamanho exato esperado da saída, em bytes.
 * @return Tamanho do resultado; a convenção de erro não é afirmável nesta revisão.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Decompression of the format produced by `zupt_lz_compress`.
 * @param[in] src Compressed input data.
 * @param[in] slen Compressed input length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] dlen Exact expected output length, in bytes.
 * @return Size of the result; the error convention cannot be stated in this revision.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
size_t zupt_lz_decompress(const uint8_t *src, size_t slen, uint8_t *dst, size_t dlen);
/**
 * @cond PORT
 * @brief Calcula o limite superior de tamanho para o resultado de `zupt_lz_compress`.
 *
 * Serve para dimensionar o buffer de destino antes da chamada, seguindo a convenção usual de
 * funções de compressão.
 *
 * A fórmula concreta não pode ser afirmada nesta revisão: a função não tem implementação em `src/`
 * nem é exercida por nenhum teste do repositório.
 * @param[in] slen tamanho, em bytes, do dado de entrada.
 * @return número de bytes necessários para comportar qualquer saída de `zupt_lz_compress` para essa
 * entrada.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Computes the upper size bound for the result of `zupt_lz_compress`.
 *
 * Used to size the destination buffer before the call, following the usual convention of
 * compression functions.
 *
 * The concrete formula cannot be stated in this revision: the function has no implementation in `src/`
 * and is not exercised by any test in the repository.
 * @param[in] slen Length of the input data, in bytes.
 * @return Number of bytes required to hold any output of `zupt_lz_compress` for this
 * input.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
size_t zupt_lz_bound(size_t slen);

/* ─── LZH (LZ77 + Huffman) ─── */
/**
 * @cond PORT
 * @brief Compressão do codec LZH (LZ77 + Huffman).
 *
 * `zupt_resolve_auto_codec` escolhe este codec fora de x86_64 com AVX2, e ele é a escolha segura
 * para portabilidade. A estrutura interna do fluxo comprimido não é afirmável nesta revisão (sem
 * implementação em `src/`).
 * @param[in] src dados de entrada.
 * @param[in] slen tamanho da entrada, em bytes.
 * @param[out] dst buffer de destino.
 * @param[in] dcap capacidade do buffer de destino, em bytes.
 * @param[in] level nível de compressão.
 * @return Tamanho do resultado escrito em `dst`; a convenção de erro não é afirmável nesta revisão.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief LZH codec compression (LZ77 + Huffman).
 *
 * `zupt_resolve_auto_codec` selects this codec outside x86_64 with AVX2, and it is the safe choice
 * for portability. The internal structure of the compressed stream cannot be stated in this revision (no
 * implementation in `src/`).
 * @param[in] src Input data.
 * @param[in] slen Input length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] dcap Destination buffer capacity, in bytes.
 * @param[in] level Compression level.
 * @return Size of the result written to `dst`; the error convention cannot be stated in this revision.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
size_t zupt_lzh_compress(const uint8_t *src, size_t slen, uint8_t *dst, size_t dcap, int level);
/**
 * @cond PORT
 * @brief Descompressão do formato produzido por `zupt_lzh_compress`.
 *
 * Precisa do histórico reconstruído pelos blocos anteriores; por isso a descompressão deste codec
 * não é independente por bloco.
 * @param[in] src dados comprimidos de entrada.
 * @param[in] slen tamanho da entrada, em bytes.
 * @param[out] dst buffer de destino.
 * @param[in] dlen tamanho exato esperado da saída, em bytes.
 * @return `ZUPT_OK` em sucesso, ou código de erro em dado malformado ou saída insuficiente.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Decompression of the format produced by `zupt_lzh_compress`.
 *
 * It requires the history rebuilt by previous blocks; therefore decompression of this codec
 * is not independent per block.
 * @param[in] src Compressed input data.
 * @param[in] slen Input length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] dlen Exact expected output length, in bytes.
 * @return `ZUPT_OK` on success, or an error code on malformed input or insufficient output.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
size_t zupt_lzh_decompress(const uint8_t *src, size_t slen, uint8_t *dst, size_t dlen);
/**
 * @cond PORT
 * @brief Calcula o limite superior de tamanho para o resultado de `zupt_lzh_compress`.
 *
 * A fórmula concreta não pode ser afirmada nesta revisão: a função não tem implementação em `src/`
 * nem é exercida por nenhum teste do repositório.
 * @param[in] slen tamanho, em bytes, do dado de entrada.
 * @return número de bytes necessários para comportar qualquer saída de `zupt_lzh_compress` para
 * essa entrada.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Computes the upper size bound for the result of `zupt_lzh_compress`.
 *
 * The concrete formula cannot be stated in this revision: the function has no implementation in `src/`
 * and is not exercised by any test in the repository.
 * @param[in] slen Length of the input data, in bytes.
 * @return Number of bytes required to hold any output of `zupt_lzh_compress` for
 * this input.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
size_t zupt_lzh_bound(size_t slen);

/* ─── Byte Prediction (order-1 context transform) ─── */
/**
 * @cond PORT
 * @brief Constrói a tabela de predição de contexto de ordem 1 a partir de dados de treino.
 *
 * O cabeçalho descreve o grupo como "Byte Prediction (order-1 context transform)": o filtro subtrai
 * a previsão do byte corrente, realçando a redundância local antes da compressão.
 * @param[in] data dados usados para estimar o contexto.
 * @param[in] len tamanho dos dados de treino, em bytes.
 * @param[out] prediction tabela de 256 entradas, preenchida com a previsão para cada byte anterior.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Builds the order-1 context prediction table from training data.
 *
 * The header describes the group as "Byte Prediction (order-1 context transform)": the filter subtracts
 * the prediction of the current byte, highlighting local redundancy before compression.
 * @param[in] data Data used to estimate the context.
 * @param[in] len Training data length, in bytes.
 * @param[out] prediction Table of 256 entries, filled with the prediction for each previous byte.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
void  zupt_predict_build(const uint8_t *data, size_t len, uint8_t prediction[256]);
/**
 * @cond PORT
 * @brief Aplica o filtro de predição (subtração da previsão) a um bloco.
 * @param[in] in dados originais.
 * @param[out] out recebe os dados residuais.
 * @param[in] len (parâmetro sem descrição manual — revisar)
 * @param[in] pred (parâmetro sem descrição manual — revisar)
 * @return `ZUPT_OK` em sucesso, ou código de erro.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Applies the prediction filter (prediction subtraction) to a block.
 * @param[in] in Original data.
 * @param[out] out Receives the residual data.
 * @param[in] len (parameter without a manual description — review)
 * @param[in] pred (parameter without a manual description — review)
 * @return `ZUPT_OK` on success, or an error code.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
void  zupt_predict_encode(const uint8_t *in, uint8_t *out, size_t len, const uint8_t pred[256]);
/**
 * @cond PORT
 * @brief Reverte o filtro de predição, reconstruindo os dados originais a partir dos resíduos.
 * @param[in] in dados residuais produzidos por `zupt_predict_encode`.
 * @param[out] out recebe os dados reconstruídos.
 * @param[in] len (parâmetro sem descrição manual — revisar)
 * @param[in] pred (parâmetro sem descrição manual — revisar)
 * @return `ZUPT_OK` em sucesso, ou código de erro.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Reverses the prediction filter, reconstructing the original data from the residuals.
 * @param[in] in Residual data produced by `zupt_predict_encode`.
 * @param[out] out Receives the reconstructed data.
 * @param[in] len (parameter without a manual description — review)
 * @param[in] pred (parameter without a manual description — review)
 * @return `ZUPT_OK` on success, or an error code.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
void  zupt_predict_decode(const uint8_t *in, uint8_t *out, size_t len, const uint8_t pred[256]);
/**
 * @cond PORT
 * @brief Estima o ganho esperado de predição para um tipo de dado.
 *
 * Usado pela heurística de escolha de codec para decidir se vale aplicar o filtro de predição.
 * @param[in] data amostra dos dados a avaliar.
 * @param[in] len tamanho da amostra, em bytes.
 * @return Estimativa de ganho; a unidade não pode ser afirmada nesta revisão por falta de
 * implementação e de testes.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Estimates the expected prediction gain for a data type.
 *
 * Used by the codec selection heuristic to decide whether it is worth applying the prediction filter.
 * @param[in] data Sample of the data to evaluate.
 * @param[in] len Sample length, in bytes.
 * @return Gain estimate; the unit cannot be stated in this revision due to the lack of an
 * implementation and of tests.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
float zupt_predict_benefit(const uint8_t *data, size_t len);

/* ─── Format I/O ─── */
/**
 * @cond PORT
 * @brief Escreve um inteiro sem sinal em formato varint em um fluxo.
 *
 * A codificação exata dos bytes não pode ser afirmada nesta revisão (função sem implementação em
 * `src/`).
 * @param[out] f fluxo de saída.
 * @param[in] v valor a escrever.
 * @return Código da família `zupt_error_t`; `ZUPT_OK` em sucesso.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Writes an unsigned integer in varint format to a stream.
 *
 * The exact byte encoding cannot be stated in this revision (function without an implementation in
 * `src/`).
 * @param[out] f Output stream.
 * @param[in] v Value to write.
 * @return Code from the `zupt_error_t` family; `ZUPT_OK` on success.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
int zupt_write_varint(FILE *f, uint64_t v);
/**
 * @cond PORT
 * @brief Lê um inteiro sem sinal em formato varint de um `FILE*`.
 * @param[out] f fluxo de entrada.
 * @param[out] v (parâmetro sem descrição manual — revisar)
 * @return `ZUPT_OK` em sucesso, ou código de erro em fim de arquivo, varint malformado ou estouro.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Reads an unsigned integer in varint format from a `FILE*`.
 * @param[out] f Input stream.
 * @param[out] v (parameter without a manual description — review)
 * @return `ZUPT_OK` on success, or an error code on end of file, malformed varint, or overflow.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
int zupt_read_varint(FILE *f, uint64_t *v);
/**
 * @cond PORT
 * @brief Codifica um inteiro sem sinal em varint dentro de um buffer.
 * @param[out] b (parâmetro sem descrição manual — revisar)
 * @param[in] v valor a codificar.
 * @return `ZUPT_OK` em sucesso, ou código de erro se a codificação não couber em `dcap`.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Encodes an unsigned integer as varint inside a buffer.
 * @param[out] b (parameter without a manual description — review)
 * @param[in] v Value to encode.
 * @return `ZUPT_OK` on success, or an error code if the encoding does not fit in `dcap`.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
int zupt_encode_varint(uint8_t *b, uint64_t v);
/**
 * @cond PORT
 * @brief Decodifica um varint a partir de um buffer.
 * @param[in] b (parâmetro sem descrição manual — revisar)
 * @param[in] blen (parâmetro sem descrição manual — revisar)
 * @param[out] v recebe o valor decodificado.
 * @return `ZUPT_OK` em sucesso, ou código de erro em varint truncado ou malformado.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Decodes a varint from a buffer.
 * @param[in] b (parameter without a manual description — review)
 * @param[in] blen (parameter without a manual description — review)
 * @param[out] v Receives the decoded value.
 * @return `ZUPT_OK` on success, or an error code on a truncated or malformed varint.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
int zupt_decode_varint(const uint8_t *b, size_t blen, uint64_t *v);

/**
 * @cond PORT
 * @brief Inicializa a lista de arquivos usada pelas APIs de arquivamento.
 * @param[out] fl lista a inicializar.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Initializes the file list used by the archiving APIs.
 * @param[out] fl List to initialize.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
void zupt_filelist_init(zupt_filelist_t *fl);
/**
 * @cond PORT
 * @brief Libera toda a memória interna de uma lista de arquivos.
 *
 * Depois desta chamada o objeto só pode ser reutilizado com nova @ref zupt_filelist_init.
 * @param[out] fl lista criada por @ref zupt_filelist_init.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Releases all internal memory of a file list.
 *
 * After this call the object may only be reused with a new @ref zupt_filelist_init.
 * @param[out] fl List created by @ref zupt_filelist_init.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
void zupt_filelist_free(zupt_filelist_t *fl);
/**
 * @cond PORT
 * @brief Acrescenta um arquivo à lista, separando caminho físico e nome no arquivo.
 * @param[out] fl lista ativa.
 * @param[in] disk_path caminho real do arquivo no sistema de arquivos.
 * @param[in] arc_path nome relativo que o arquivo terá dentro do contêiner.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Adds a file to the list, separating the physical path from the name the file has inside the archive.
 * @param[out] fl Active list.
 * @param[in] disk_path Real path of the file on the filesystem.
 * @param[in] arc_path Relative name the file will have inside the container.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
void zupt_filelist_add(zupt_filelist_t *fl, const char *disk_path, const char *arc_path);
/**
 * @cond PORT
 * @brief Percorre um diretório e acrescenta recursivamente seus arquivos à lista.
 * @param[out] fl lista ativa.
 * @param[in] path diretório a percorrer.
 * @param[in] base prefixo removido dos caminhos para formar os nomes internos.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Walks a directory and recursively adds its files to the list.
 * @param[out] fl Active list.
 * @param[in] path Directory to walk.
 * @param[in] base Prefix removed from the paths to form the internal names.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
void zupt_collect_files(zupt_filelist_t *fl, const char *path, const char *base);

/**
 * @cond PORT
 * @brief Cria um contêiner `.zupt` a partir de listas de caminhos físicos e nomes internos.
 *
 * Permite nomes no arquivamento diferentes dos caminhos de origem, o que o torna a entrada usada
 * por `libzupt.cpp` e pelos bindings.
 *
 * O comportamento concreto (compressão, criptografia, dedup) é governado por `opts`.
 * @param[in] out caminho do contêiner a criar.
 * @param[in] arc nomes internos dos arquivos, um por elemento.
 * @param[in] disk caminhos físicos correspondentes a `arc`.
 * @param[in] n quantidade de elementos em `arc` e `disk`.
 * @param[out] opts opções do contêiner.
 * @return `ZUPT_OK` em sucesso, ou código de erro da família `zupt_error_t`.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Creates a `.zupt` container from lists of physical paths and internal names.
 *
 * It allows archive names that differ from the source paths, which makes it the entry point used
 * by `libzupt.cpp` and by the bindings.
 *
 * The concrete behavior (compression, encryption, deduplication) is governed by `opts`.
 * @param[in] out Path of the container to create.
 * @param[in] arc Internal names of the files, one per element.
 * @param[in] disk Physical paths corresponding to `arc`.
 * @param[in] n Number of elements in `arc` and `disk`.
 * @param[out] opts Container options.
 * @return `ZUPT_OK` on success, or an error code from the `zupt_error_t` family.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
zupt_error_t zupt_compress_files(const char *out, const char **arc, const char **disk, int n, zupt_options_t *opts);
/**
 * @cond PORT
 * @brief Extrai todos os arquivos de um contêiner `.zupt` para um diretório.
 * @param[in] arc caminho do contêiner.
 * @param[in] dir diretório de destino.
 * @param[out] opts opções (incluem a chave para contêineres cifrados).
 * @return `ZUPT_OK` em sucesso, ou código de erro (autenticação, E/S, formato).
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Extracts all files from a `.zupt` container to a directory.
 * @param[in] arc Path of the container.
 * @param[in] dir Destination directory.
 * @param[out] opts Options (include the key for encrypted containers).
 * @return `ZUPT_OK` on success, or an error code (authentication, I/O, format).
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
zupt_error_t zupt_extract_archive(const char *arc, const char *dir, zupt_options_t *opts);
/**
 * @cond PORT
 * @brief Lista o conteúdo de um contêiner `.zupt` sem extrair os arquivos.
 * @param[in] arc caminho do contêiner.
 * @param[out] opts opções de leitura.
 * @return `ZUPT_OK` em sucesso, ou código de erro.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Lists the contents of a `.zupt` container without extracting the files.
 * @param[in] arc Path of the container.
 * @param[out] opts Read options.
 * @return `ZUPT_OK` on success, or an error code.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
zupt_error_t zupt_list_archive(const char *arc, zupt_options_t *opts);
/**
 * @cond PORT
 * @brief Verifica a integridade de um contêiner `.zupt` sem materializar os arquivos.
 * @param[in] arc caminho do contêiner.
 * @param[out] opts opções de leitura.
 * @return `ZUPT_OK` quando o contêiner é íntegro, ou código de erro indicando a falha.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Checks the integrity of a `.zupt` container without materializing the files.
 * @param[in] arc Path of the container.
 * @param[out] opts Read options.
 * @return `ZUPT_OK` when the container is intact, or an error code indicating the failure.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
zupt_error_t zupt_test_archive(const char *arc, zupt_options_t *opts);

/* ─── Hybrid PQ KEM (ML-KEM-768 + X25519) ─── */
/**
 * @cond PORT
 * @brief Gera o par de chaves híbrido pós-quântico (ML-KEM-768 + X25519) em um arquivo.
 *
 * A geração usa @ref zupt_x25519_base e os primitivos de `include/zupt_mlkem.h`; o formato do
 * arquivo de chave é o descrito por `ZUPT_KEY_FORMAT_VERSION`.
 * @param[in] keyfile arquivo onde o par de chaves será gravado.
 * @return 0 em sucesso, ou código de erro.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Generates the post-quantum hybrid key pair (ML-KEM-768 + X25519) in a file.
 *
 * Generation uses @ref zupt_x25519_base and the primitives from `include/zupt_mlkem.h`; the key file
 * format is the one described by `ZUPT_KEY_FORMAT_VERSION`.
 * @param[in] keyfile File where the key pair will be written.
 * @return 0 on success, or an error code.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
int zupt_hybrid_keygen(const char *keyfile);
/**
 * @cond PORT
 * @brief Deriva o arquivo de chave pública a partir do arquivo de chave privada.
 * @param[in] privfile arquivo de chave privada.
 * @param[in] pubfile arquivo de chave pública a criar.
 * @return 0 em sucesso, ou código de erro.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Derives the public key file from the private key file.
 * @param[in] privfile Private key file.
 * @param[in] pubfile Public key file to create.
 * @return 0 on success, or an error code.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
int zupt_hybrid_export_pubkey(const char *privfile, const char *pubfile);
/**
 * @cond PORT
 * @brief Estabelece a sessão híbrida para criptografar, a partir de chave pública em arquivo.
 *
 * Executa o encapsulamento híbrido e preenche o cabeçalho que deve ser escrito no contêiner e
 * enviado ao destinatário.
 * @param[out] kr keyring que receberá as chaves de sessão.
 * @param[in] pubkeyfile chave pública do destinatário.
 * @param[out] enc_hdr recebe o cabeçalho de sessão.
 * @param[out] enc_hdr_len recebe o tamanho do cabeçalho.
 * @return 0 em sucesso, ou código de erro.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Establishes the hybrid session for encryption, from a public key in a file.
 *
 * Performs the hybrid encapsulation and fills the header that must be written to the container and
 * sent to the recipient.
 * @param[out] kr Keyring that will receive the session keys.
 * @param[in] pubkeyfile Recipient's public key.
 * @param[out] enc_hdr Receives the session header.
 * @param[out] enc_hdr_len Receives the header length.
 * @return 0 on success, or an error code.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
int zupt_hybrid_encrypt_init(zupt_keyring_t *kr, const char *pubkeyfile,
                              uint8_t *enc_hdr, size_t *enc_hdr_len);
/**
 * @cond PORT
 * @brief Estabelece a sessão híbrida para descriptografar, a partir de chave privada em arquivo.
 * @param[out] kr keyring que receberá as chaves de sessão.
 * @param[in] privkeyfile arquivo de chave privada.
 * @param[in] enc_hdr cabeçalho de sessão recebido.
 * @param[in] enc_hdr_len tamanho do cabeçalho recebido.
 * @return 0 em sucesso, ou código de erro.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Establishes the hybrid session for decryption, from a private key in a file.
 * @param[out] kr Keyring that will receive the session keys.
 * @param[in] privkeyfile Private key file.
 * @param[in] enc_hdr Received session header.
 * @param[in] enc_hdr_len Length of the received header.
 * @return 0 on success, or an error code.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
int zupt_hybrid_decrypt_init(zupt_keyring_t *kr, const char *privkeyfile,
                              const uint8_t *enc_hdr, size_t enc_hdr_len);
/* In-memory variants: take the key material directly from a buffer instead of
 * a file path, so callers never have to stage (private) keys on disk. */
/**
 * @cond PORT
 * @brief Variante em memória de @ref zupt_hybrid_encrypt_init, com chave pública em buffer.
 *
 * O comentário do cabeçalho explica a finalidade: evitar que material de chave seja gravado
 * temporariamente em disco.
 * @param[out] kr keyring que receberá as chaves de sessão.
 * @param[in] pubkey chave pública em buffer.
 * @param[in] pubkey_len tamanho da chave pública, em bytes.
 * @param[out] enc_hdr recebe o cabeçalho de sessão.
 * @param[out] enc_hdr_len recebe o tamanho do cabeçalho.
 * @return 0 em sucesso, ou código de erro.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief In-memory variant of @ref zupt_hybrid_encrypt_init, with the public key in a buffer.
 *
 * The header comment explains the purpose: avoid having key material temporarily written to disk.
 * @param[out] kr Keyring that will receive the session keys.
 * @param[in] pubkey Public key in a buffer.
 * @param[in] pubkey_len Public key length, in bytes.
 * @param[out] enc_hdr Receives the session header.
 * @param[out] enc_hdr_len Receives the header length.
 * @return 0 on success, or an error code.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
int zupt_hybrid_encrypt_init_mem(zupt_keyring_t *kr,
                                  const uint8_t *pubkey, size_t pubkey_len,
                                  uint8_t *enc_hdr, size_t *enc_hdr_len);
/**
 * @cond PORT
 * @brief Variante em memória de @ref zupt_hybrid_decrypt_init, com chave privada em buffer.
 * @param[out] kr keyring que receberá as chaves de sessão.
 * @param[in] privkey chave privada em buffer.
 * @param[in] privkey_len tamanho da chave privada, em bytes.
 * @param[in] enc_hdr cabeçalho de sessão recebido.
 * @param[in] enc_hdr_len tamanho do cabeçalho recebido.
 * @return 0 em sucesso, ou código de erro.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief In-memory variant of @ref zupt_hybrid_decrypt_init, with the private key in a buffer.
 * @param[out] kr Keyring that will receive the session keys.
 * @param[in] privkey Private key in a buffer.
 * @param[in] privkey_len Private key length, in bytes.
 * @param[in] enc_hdr Received session header.
 * @param[in] enc_hdr_len Length of the received header.
 * @return 0 on success, or an error code.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
int zupt_hybrid_decrypt_init_mem(zupt_keyring_t *kr,
                                  const uint8_t *privkey, size_t privkey_len,
                                  const uint8_t *enc_hdr, size_t enc_hdr_len);

/**
 * @cond PORT
 * @brief Devolve a descrição legível de um código de erro.
 * @param[in] e código de erro da família `zupt_error_t`.
 * @return Cadeia de caracteres estática; nunca deve ser liberada pelo chamador.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Returns the human-readable description of an error code.
 * @param[in] e Error code from the `zupt_error_t` family.
 * @return Static string; it must never be freed by the caller.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
const char *zupt_strerror(zupt_error_t e);
/**
 * @cond PORT
 * @brief Devolve o nome legível de um identificador de codec.
 * @param[in] id identificador do codec (ver macros `ZUPT_CODEC_*`).
 * @return Cadeia de caracteres estática com o nome do codec.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Returns the human-readable name of a codec identifier.
 * @param[in] id Codec identifier (see the `ZUPT_CODEC_*` macros).
 * @return Static string with the codec name.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
const char *zupt_codec_name(uint16_t id);
/**
 * @cond PORT
 * @brief Preenche uma estrutura de opções com os valores padrão.
 *
 * Necessário antes de usar `zupt_options_t`, cujas macros de definição de valores dependem de um
 * estado inicial coerente.
 * @param[out] o estrutura a inicializar.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Fills an options structure with the default values.
 *
 * Required before using `zupt_options_t`, whose value-setting macros depend on a consistent initial
 * state.
 * @param[out] o Structure to initialize.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
void zupt_default_options(zupt_options_t *o);
/**
 * @cond PORT
 * @brief Formata uma contagem de bytes em texto legível para exibição.
 * @param[in] bytes quantidade de bytes a formatar.
 * @param[out] buf buffer de destino da cadeia formatada.
 * @param[in] cap capacidade do buffer, em bytes.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Formats a byte count as human-readable text for display.
 * @param[in] bytes Number of bytes to format.
 * @param[out] buf Destination buffer for the formatted string.
 * @param[in] cap Buffer capacity, in bytes.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
void zupt_format_size(uint64_t bytes, char *buf, size_t cap);

/* Resolve ZUPT_CODEC_AUTO to a concrete codec based on hardware.
 * On x86_64 with AVX2: VaptVupt (fast ANS+SIMD decode).
 * On all other arches:  Zupt-LZHP (no SIMD dependency).
 * Decompression of ALL codecs works on ALL architectures. */
/**
 * @cond PORT
 * @brief Resolve `ZUPT_CODEC_AUTO` em um codec concreto, conforme o hardware.
 *
 * O comentário do cabeçalho define a política: em x86_64 com AVX2 escolhe VaptVupt (decodificação
 * ANS + SIMD mais rápida); em todas as outras arquiteturas escolhe Zupt-LZHP, que não depende de
 * instruções SIMD.
 *
 * A descompressão de todos os codecs funciona em todas as arquiteturas, o que torna a escolha
 * segura no envio da carga comprimida.
 * @return Identificador concreto de codec (uma das macros `ZUPT_CODEC_*`).
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Resolves `ZUPT_CODEC_AUTO` to a concrete codec, according to the hardware.
 *
 * The header comment defines the policy: on x86_64 with AVX2 it selects VaptVupt (the fastest ANS + SIMD
 * decoding); on all other architectures it selects Zupt-LZHP, which does not depend on SIMD instructions.
 *
 * Decompression of all codecs works on all architectures, which makes the choice safe when sending the
 * compressed payload.
 * @return Concrete codec identifier (one of the `ZUPT_CODEC_*` macros).
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
uint16_t zupt_resolve_auto_codec(void);

/* ─── Full-Disk Backup/Restore ─── */
/**
 * @cond PORT
 * @def ZUPT_FLAG_DISK_IMAGE
 * @brief Flag de arquivo indicando que o conteúdo é uma imagem de disco.
 * @details O campo `global_flags` de @ref zupt_archive_header_t é um
 * bitfield; este bit informa ao leitor que o conteúdo deve ser
 * tratado como imagem bruta, por exemplo para restauração direta.
 * @note    Não há, em `src/`, código que consulte este bit.
 * @endcond
 * @cond INGLES
 * @def ZUPT_FLAG_DISK_IMAGE
 * @brief File flag indicating that the content is a disk image.
 * @details The `global_flags` field of @ref zupt_archive_header_t is a
 * bitfield; this bit tells the reader that the content must be
 * treated as a raw image, for example for direct restoration.
 * @note    There is no code in `src/` that consults this bit.
 * @endcond */
#define ZUPT_FLAG_DISK_IMAGE   (1u << 6)  /* Archive contains a raw disk/partition image */

/* Compress a raw block device or file as a disk image.
 * Reads source in block_size chunks, detects zero/sparse regions,
 * compresses non-zero blocks. Supports encryption + PQ. */
/**
 * @cond PORT
 * @brief Cria um contêiner `.zupt` a partir de uma imagem de disco ou dispositivo de blocos.
 *
 * O cabeçalho descreve a estratégia: lê a origem em blocos de `block_size`, detecta regiões de
 * zeros/radicidade e comprime apenas os blocos não nulos; suporta criptografia e o modo
 * pós-quântico.
 *
 * Envolve leitura direta de dispositivos, portanto depende de privilégios de SO.
 * @param[in] output_path contêiner `.zupt` a criar.
 * @param[in] source_path dispositivo de blocos ou arquivo de origem.
 * @param[out] opts opções; incluem `block_size` e o sinalizador `ZUPT_FLAG_DISK_IMAGE`.
 * @return `ZUPT_OK` em sucesso, ou código de erro.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Creates a `.zupt` container from a disk image or block device.
 *
 * The header describes the strategy: it reads the source in blocks of `block_size`, detects zero/sparse
 * regions and compresses only the non-zero blocks; it supports encryption and the post-quantum mode.
 *
 * It involves direct reads from devices, therefore it depends on OS privileges.
 * @param[in] output_path `.zupt` container to create.
 * @param[in] source_path Source block device or file.
 * @param[out] opts Options; include `block_size` and the `ZUPT_FLAG_DISK_IMAGE` flag.
 * @return `ZUPT_OK` on success, or an error code.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
zupt_error_t zupt_disk_backup(const char *output_path, const char *source_path,
                               zupt_options_t *opts);

/* Restore a disk image archive to a block device or file.
 * Writes blocks sequentially, restoring sparse regions as zeros. */
/**
 * @cond PORT
 * @brief Restaura uma imagem de disco gravada por @ref zupt_disk_backup.
 *
 * Grava os blocos em sequência, reconstituindo as regiões radiciais como zeros.
 * @param[in] archive_path contêiner a restaurar.
 * @param[in] target_path dispositivo de blocos ou arquivo de destino.
 * @param[out] opts opções de restauração.
 * @return `ZUPT_OK` em sucesso, ou código de erro.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Restores a disk image written by @ref zupt_disk_backup.
 *
 * Writes the blocks in sequence, reconstituting the sparse regions as zeros.
 * @param[in] archive_path Container to restore.
 * @param[in] target_path Destination block device or file.
 * @param[out] opts Restoration options.
 * @return `ZUPT_OK` on success, or an error code.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
zupt_error_t zupt_disk_restore(const char *archive_path, const char *target_path,
                                zupt_options_t *opts);

/* ─── Internal Block I/O (used by format + disk modules) ─── */
/**
 * @cond PORT
 * @brief Lê o cabeçalho e a carga de um bloco do contêiner.
 *
 * Símbolo de uso interno dos módulos de formato; não faz parte da API pública.
 * @param[out] f fluxo posicionado no início do bloco.
 * @param[out] b recebe o bloco lido.
 * @return `ZUPT_OK` em sucesso, ou código de erro de E/S/formato.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Reads the header and payload of a container block.
 *
 * Internal symbol for use by the format modules; it is not part of the public API.
 * @param[out] f Stream positioned at the beginning of the block.
 * @param[out] b Receives the block read.
 * @return `ZUPT_OK` on success, or an I/O/format error code.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
zupt_error_t read_block(FILE *f, zupt_block_t *b);
/**
 * @cond PORT
 * @brief Lê e valida o cabeçalho de um contêiner cifrado.
 * @param[out] f fluxo posicionado no início do arquivo.
 * @param[out] hdr recebe o cabeçalho lido.
 * @param[out] opts recebe as opções derivadas do cabeçalho.
 * @return `ZUPT_OK` em sucesso, ou `ZUPT_ERR_MAGIC`/`ZUPT_ERR_FORMAT` em cabeçalho inválido.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Reads and validates the header of an encrypted container.
 * @param[out] f Stream positioned at the beginning of the file.
 * @param[out] hdr Receives the header read.
 * @param[out] opts Receives the options derived from the header.
 * @return `ZUPT_OK` on success, or `ZUPT_ERR_MAGIC`/`ZUPT_ERR_FORMAT` on an invalid header.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
zupt_error_t read_enc_header(FILE *f, zupt_archive_header_t *hdr, zupt_options_t *opts);
/**
 * @cond PORT
 * @brief Autentica, descriptografa e descomprime um bloco lido do contêiner.
 *
 * A ordem é sempre verificar-MAC-depois-decriptografar; o bloco só é entregue autenticado. O
 * `block_seq` entra na composição do nonce.
 * @param[in] b bloco lido por @ref read_block.
 * @param[in] kr keyring com as chaves de sessão.
 * @param[in] block_seq número de sequência do bloco, usado no nonce.
 * @param[out] out recebe o buffer alocado com a carga.
 * @param[out] olen recebe o tamanho da carga.
 * @return `ZUPT_OK` em sucesso, ou `ZUPT_ERR_AUTH_FAIL` quando a autenticação falha.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Authenticates, decrypts and decompresses a block read from the container.
 *
 * The order is always verify-MAC-then-decrypt; the block is delivered only after authentication. The
 * `block_seq` value enters the nonce composition.
 * @param[in] b Block read by @ref read_block.
 * @param[in] kr Keyring with the session keys.
 * @param[in] block_seq Block sequence number, used in the nonce.
 * @param[out] out Receives the allocated buffer with the payload.
 * @param[out] olen Receives the payload length.
 * @return `ZUPT_OK` on success, or `ZUPT_ERR_AUTH_FAIL` when authentication fails.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
zupt_error_t decompress_block(const zupt_block_t *b, const zupt_keyring_t *kr,
                               uint64_t block_seq, uint8_t **out, size_t *olen);
/**
 * @cond PORT
 * @brief Escreve o cabeçalho de um contêiner cifrado.
 * @param[out] out fluxo de saída.
 * @param[out] hdr cabeçalho a gravar.
 * @param[out] opts opções usadas na geração do cabeçalho.
 * @return `ZUPT_OK` em sucesso, ou código de erro de E/S.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Writes the header of an encrypted container.
 * @param[out] out Output stream.
 * @param[out] hdr Header to write.
 * @param[out] opts Options used in generating the header.
 * @return `ZUPT_OK` on success, or an I/O error code.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
zupt_error_t write_enc_header(FILE *out, zupt_archive_header_t *hdr,
                               zupt_options_t *opts);
/**
 * @cond PORT
 * @brief Escreve um byte em little-endian em um fluxo.
 * @param[out] f fluxo de saída.
 * @param[in] v valor a escrever.
 * @return 0 em sucesso, ou código de erro de E/S.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Writes a byte in little-endian format to a stream.
 * @param[out] f Output stream.
 * @param[in] v Value to write.
 * @return 0 on success, or an I/O error code.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
int zupt_w8(FILE *f, uint8_t v);
/**
 * @cond PORT
 * @brief Escreve um inteiro de 16 bits little-endian em um fluxo.
 * @param[out] f fluxo de saída.
 * @param[in] v valor a escrever.
 * @return 0 em sucesso, ou código de erro de E/S.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Writes a 16-bit little-endian integer to a stream.
 * @param[out] f Output stream.
 * @param[in] v Value to write.
 * @return 0 on success, or an I/O error code.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
int zupt_w16le(FILE *f, uint16_t v);
/**
 * @cond PORT
 * @brief Escreve um inteiro de 64 bits little-endian em um fluxo.
 * @param[out] f fluxo de saída.
 * @param[in] v valor a escrever.
 * @return 0 em sucesso, ou código de erro de E/S.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Writes a 64-bit little-endian integer to a stream.
 * @param[out] f Output stream.
 * @param[in] v Value to write.
 * @return 0 on success, or an I/O error code.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
int zupt_w64le(FILE *f, uint64_t v);

/* ─── Block-Level Deduplication ─── */
/**
 * @cond PORT
 * @def ZUPT_DEDUP_MAX_ENTRIES
 * @brief Limite de entradas da tabela de desduplicação em memória (2 Mi).
 * @details Dimensiona o índice interno de @ref zupt_dedup_ctx_t.
 * @see ZUPT_BLOCK_DEDUP_REF
 * @endcond
 * @cond INGLES
 * @def ZUPT_DEDUP_MAX_ENTRIES
 * @brief Limit on the entries of the in-memory deduplication table (2 Mi).
 * @details Sizes the internal index of @ref zupt_dedup_ctx_t.
 * @see ZUPT_BLOCK_DEDUP_REF
 * @endcond */
#define ZUPT_DEDUP_MAX_ENTRIES  (2 * 1024 * 1024)  /* 2M entries, ~48MB RAM */

/**
 * @cond PORT
 * @typedef  struct zupt_dedup_ctx zupt_dedup_ctx_t
 * @brief    Contexto opaco do índice de desduplicação em memória.
 * @details    Os membros não são expostos: o layout é interno ao módulo de
 * desduplicação. O tamanho máximo da tabela é
 * @ref ZUPT_DEDUP_MAX_ENTRIES.
 * @endcond
 * @cond INGLES
 * @typedef  struct zupt_dedup_ctx zupt_dedup_ctx_t
 * @brief    Opaque context of the in-memory deduplication index.
 * @details    The members are not exposed: the layout is internal to the
 * deduplication module. The maximum table size is
 * @ref ZUPT_DEDUP_MAX_ENTRIES.
 * @endcond */
typedef struct zupt_dedup_ctx zupt_dedup_ctx_t;

/**
 * @cond PORT
 * @brief Cria o contexto de deduplicação em nível de bloco.
 *
 * O contexto guarda a tabela de impressões digitais de blocos já vistos; o limite de entradas é
 * `ZUPT_DEDUP_MAX_ENTRIES`, cujo comentário no cabeçalho estima cerca de 48 MB de RAM.
 *
 * Serve tanto a arquivagem comum quanto à imagem de disco, onde regiões repetidas são frequentes.
 * @return Ponteira para o contexto criado, ou `NULL` se a alocação falhar.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Creates the block-level deduplication context.
 *
 * The context keeps the table of fingerprints of the blocks already seen; the entry limit is
 * `ZUPT_DEDUP_MAX_ENTRIES`, whose header comment estimates about 48 MB of RAM.
 *
 * It serves both regular archiving and disk images, where repeated regions are frequent.
 * @return Pointer to the created context, or `NULL` if the allocation fails.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
zupt_dedup_ctx_t *zupt_dedup_init(void);
/**
 * @cond PORT
 * @brief Libera o contexto de deduplicação.
 * @param[out] ctx contexto criado por @ref zupt_dedup_init.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Releases the deduplication context.
 * @param[out] ctx Context created by @ref zupt_dedup_init.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
void zupt_dedup_free(zupt_dedup_ctx_t *ctx);
/**
 * @cond PORT
 * @brief Consulta a tabela de deduplicação por impressão digital de bloco.
 * @param[out] ctx contexto ativo.
 * @param[in] fingerprint impressão digital do bloco a procurar.
 * @param[out] ref_offset recebe a posição, no contêiner, do bloco idêntico já gravado.
 * @param[out] ref_size recebe o tamanho desse bloco.
 * @return Indica se houve correspondência; ver nota.
 * @note Convenção de retorno não pode ser afirmada nesta revisão: o grupo de deduplicação não
 * possui implementação em `src/` nem testes em `tests/`.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Looks up the deduplication table by block fingerprint.
 * @param[out] ctx Active context.
 * @param[in] fingerprint Fingerprint of the block to look up.
 * @param[out] ref_offset Receives the position, in the container, of the identical block already
 * written.
 * @param[out] ref_size Receives the size of that block.
 * @return Indicates whether there was a match; see the note.
 * @note The return convention cannot be stated in this revision: the deduplication group has no
 * implementation in `src/` and no tests in `tests/`.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
int  zupt_dedup_lookup(zupt_dedup_ctx_t *ctx, uint64_t fingerprint,
                       uint64_t *ref_offset, uint32_t *ref_size);
/**
 * @cond PORT
 * @brief Registra um bloco na tabela de deduplicação.
 * @param[out] ctx contexto ativo.
 * @param[in] fingerprint impressão digital do bloco.
 * @param[in] block_offset posição do bloco no contêiner.
 * @param[in] block_size tamanho do bloco.
 * @return Indica sucesso ou rejeição (por exemplo tabela cheia); ver nota.
 * @note Convenção de retorno não pode ser afirmada nesta revisão: o grupo de deduplicação não
 * possui implementação em `src/` nem testes em `tests/`.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Records a block in the deduplication table.
 * @param[out] ctx Active context.
 * @param[in] fingerprint Fingerprint of the block.
 * @param[in] block_offset Position of the block in the container.
 * @param[in] block_size Size of the block.
 * @return Indicates success or rejection (for example, a full table); see the note.
 * @note The return convention cannot be stated in this revision: the deduplication group has no
 * implementation in `src/` and no tests in `tests/`.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
int  zupt_dedup_insert(zupt_dedup_ctx_t *ctx, uint64_t fingerprint,
                       uint64_t block_offset, uint32_t block_size);
/**
 * @cond PORT
 * @brief Acumula a estatística de bytes economizados por uma correspondência.
 * @param[out] ctx contexto ativo.
 * @param[in] saved_bytes quantidade de bytes economizados neste acerto.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Accumulates the statistic of bytes saved by a match.
 * @param[out] ctx Active context.
 * @param[in] saved_bytes Number of bytes saved in this match.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
void zupt_dedup_record_hit(zupt_dedup_ctx_t *ctx, uint64_t saved_bytes);
/**
 * @cond PORT
 * @brief Conta um bloco examinado nas estatísticas de deduplicação.
 * @param[out] ctx contexto ativo.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Counts one examined block in the deduplication statistics.
 * @param[out] ctx Active context.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
void zupt_dedup_record_block(zupt_dedup_ctx_t *ctx);
/**
 * @cond PORT
 * @brief Devolve os contadores acumulados de deduplicação.
 * @param[in] ctx contexto ativo.
 * @param[out] blocks_seen recebe o total de blocos examinados.
 * @param[out] blocks_deduped recebe o total de blocos substituídos por referência.
 * @param[out] bytes_saved recebe o total de bytes economizados.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Returns the accumulated deduplication counters.
 * @param[in] ctx Active context.
 * @param[out] blocks_seen Receives the total number of blocks examined.
 * @param[out] blocks_deduped Receives the total number of blocks replaced by a reference.
 * @param[out] bytes_saved Receives the total number of bytes saved.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
void zupt_dedup_stats(const zupt_dedup_ctx_t *ctx,
                      uint64_t *blocks_seen, uint64_t *blocks_deduped,
                      uint64_t *bytes_saved);
/**
 * @cond PORT
 * @brief Escreve no contêiner um registro de referência a um bloco já gravado.
 *
 * É o mecanismo que permite economizar espaço: em vez de regravar o bloco, grava-se uma referência
 * com a posição, o tamanho original e a_checksum, que a restauração usa para reconstruir o
 * conteúdo.
 * @param[out] out fluxo do contêiner.
 * @param[in] ref_offset posição do bloco referenciado.
 * @param[in] orig_size tamanho original do bloco.
 * @param[in] orig_checksum checksum do bloco referenciado, usada na validação.
 * @return Código da operação de escrita; ver nota.
 * @note Convenção de retorno não pode ser afirmada nesta revisão: o grupo de deduplicação não
 * possui implementação em `src/` nem testes em `tests/`.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 * @endcond
 * @cond INGLES
 * @brief Writes to the container a record referencing an already written block.
 *
 * It is the mechanism that enables space savings: instead of rewriting the block, a reference is
 * written with the position, the original size and the checksum, which restoration uses to rebuild the
 * content.
 * @param[out] out Container stream.
 * @param[in] ref_offset Position of the referenced block.
 * @param[in] orig_size Original size of the block.
 * @param[in] orig_checksum Checksum of the referenced block, used for validation.
 * @return Code of the write operation; see the note.
 * @note The return convention cannot be stated in this revision: the deduplication group has no
 * implementation in `src/` and no tests in `tests/`.
 * @note In this revision of the repository, the symbol is declared in this header but has no
 * definition in `src/`.
 * @endcond */
int  zupt_dedup_write_ref(FILE *out, uint64_t ref_offset,
                          uint32_t orig_size, uint64_t orig_checksum);

#endif /* ZUPT_H */
