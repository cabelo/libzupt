/*
 * Zupt — Backup-oriented compression with AES-256 encryption
 * Copyright (c) 2026 Cristian Cezar Moisés
 * SPDX-License-Identifier: MIT
 */
/**
 * @file   zupt.h
 * @brief  Cabeçalho público da libzupt: constantes de formato, primitivas criptográficas e API de arquivamento.
 * @details Este é o guarda-chuva de inclusão da biblioteca. Ele declara:
 *          - macros de formato (magic, versões de formato, limites, flags
 *            globais, tipos de cifra, tipos de bloco, identificadores de codec);
 *          - as estruturas do formato em disco (`zupt_archive_header_t`,
 *            `zupt_footer_t`), empacotadas byte a byte e serializadas em
 *            little-endian;
 *          - as estruturas em memória (`zupt_index_entry_t`, `zupt_block_t`,
 *            `zupt_keyring_t`, `zupt_filelist_t`, `zupt_options_t`);
 *          - auxiliares `static inline`: serialização little-endian, limpeza
 *            segura de memória e teste de arquivo regular;
 *          - as primitivas criptográficas implementadas nesta árvore
 *            (SHA-256, AES-256, HMAC-SHA256, PBKDF2, AES-256-CTR, derivação de
 *            chaves, envelope Encrypt-then-MAC, XXH64, aleatoriedade,
 *            locking de memória);
 *          - a API de arquivamento, compressão, extração, deduplicação e
 *            imagem de disco.
 *
 *          Endianidade: os campos numéricos multibyte do formato em disco são
 *          little-endian. Os helpers `zupt_le*_put`/`zupt_le*_get` fazem a
 *          conversão byte a byte, então o resultado não depende da endianidade
 *          do host. Os tipos `zupt_archive_header_t` e `zupt_footer_t` usam
 *          o pragma `pack(push,1)`: gravá-los como um bloco único de bytes só
 *          produz little-endian em host little-endian, motivo pelo qual a
 *          serialização usa os helpers acima em vez de escrita direta dos
 *          structs.
 *
 *          Convenção de retorno: a maior parte da API devolve `zupt_error_t`
 *          (0 = sucesso, negativos = erro). As funções do grupo de cifra que
 *          devolvem `int` seguem a mesma ideia. As que devolvem `uint8_t *`
 *          devolvem `NULL` em erro (ver a documentação de cada uma).
 * @warning Nesta revisão do repositório, o grupo de arquivamento (compressão,
 *          extração, listagem, teste, LZ/LZH/byte-prediction, varint,
 *          filelist, `zupt_strerror`, `zupt_codec_name`, `zupt_default_options`,
 *          `zupt_format_size`, `zupt_resolve_auto_codec`, imagem de disco e
 *          deduplicação) é declarado neste cabeçalho, mas <b>não possui
 *          definição em `src/`</b>. A cada uma dessas funções está anexada a
 *          mesma nota. Ver docs/doxygen/limitacoes.md e
 *          docs/doxygen/inventario.md.
 * @warning Há divergência de versionamento declarativo nesta árvore:
 *           `ZUPT_VERSION_STRING` é "2.1.5" aqui; `LIBZUPT_VERSION_STRING` é
 *           "1.0.15" em libzupt_version.h e é o valor usado pelo CMakeLists.txt
 *           para `PROJECT_VERSION`/SOVERSION. As duas são documentadas como
 *           estão, não harmonizadas.
 * @see include/libzupt_version.h, include/zupt_cxx.h, include/zupt_mlkem.h,
 *      include/zupt_x25519.h, include/zupt_acsl.h, docs/FORMAT.md
 */
#ifndef ZUPT_H
#define ZUPT_H

/* Feature test macros — must precede all system includes.
 * _DEFAULT_SOURCE gives us lstat() on glibc without -D_GNU_SOURCE. */
/**
 * @def _DEFAULT_SOURCE
 * @brief Macro de teste de recurso da glibc, definido quando ausente.
 * @details Definido como 1 apenas quando nem `_DEFAULT_SOURCE` nem
 *          `_GNU_SOURCE` já foram definidos, e sempre antes de qualquer
 *          inclusão de sistema. É o que torna `lstat()` visível na glibc sem
 *          exigir `-D_GNU_SOURCE` no compile do consumidor.
 * @note Não altera o contrato das funções: apenas expõe interfaces POSIX.
 */
#if !defined(_DEFAULT_SOURCE) && !defined(_GNU_SOURCE)
  #define _DEFAULT_SOURCE 1
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

/**
 * @def ZUPT_PATH_SEP
 * @brief Separador de componentes de caminho da plataforma.
 * @details Recebe a barra invertida quando compilado para Windows (`_WIN32`)
 *          e a barra normal nos demais sistemas. Definido dentro do mesmo
 *          condição de pré-processador que escolhe os cabeçalhos de sistema, por isso sempre
 *          existe em qualquer configuração. Não há normalização de caminhos
 *          em disco: o arquivo guarda o separador do sistema que o criou.
 */
/**
 * @def zupt_mkdir(p)
 * @brief Cria o diretório `p` com permissões de padrão POSIX (0755).
 * @details Em `_WIN32` expande para `_mkdir(p)`, que ignora o argumento de
 *          modo; nos demais sistemas para `mkdir(p, 0755)`. Não há
 *          tratamento de erro embutido: o chamador deve observar o valor
 *          devolvido pela chamada de sistema.
 * @param[in] p Caminho do diretório a criar.
 */
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
 * @def ZUPT_VERSION_STRING
 * @brief Cadeia de versão declarada por este cabeçalho (`"2.1.5"`).
 * @warning Este valor <b>não</b> é a versão da biblioteca compartilhada.
 *          `include/libzupt_version.h` define `LIBZUPT_VERSION_STRING` como
 *          `"1.0.15"`, e é esse valor que o CMakeLists.txt usa para
 *          `PROJECT_VERSION` e para o SOVERSION do objeto compartilhado.
 *          `CHANGES.md`/`README.md` mencionam ainda `2.0.0`. Nesta revisão as
 *          divergências são documentadas como estão, não corrigidas.
 * @see LIBZUPT_VERSION_STRING
 */
#define ZUPT_VERSION_STRING "2.1.5"
/**
 * @def ZUPT_FORMAT_MAJOR
 * @brief Componente maior da versão de formato de arquivo suportada (1).
 * @details É escrito em `version_major` de @ref zupt_archive_header_t.
 */
#define ZUPT_FORMAT_MAJOR   1
/**
 * @def ZUPT_FORMAT_MINOR
 * @brief Componente menor da versão de formato de arquivo suportada (4).
 * @details É escrito em `version_minor` de @ref zupt_archive_header_t.
 *          A combinação `1.4` identifica o layout descrito em
 *          @ref page-formato.
 */
#define ZUPT_FORMAT_MINOR   4

/**
 * @def ZUPT_MAGIC_0
 * @brief Primeiro byte da assinatura de 6 bytes do cabeçalho de arquivo: `0x5A` (`'Z'`).
 * @details Os seis bytes, nesta ordem, são `0x5A 0x55 0x50 0x54` (a cadeia
 *          `"ZUPT"`), seguidos de `0x1A` (byte de controle ASCII de
 *          substituto/fim de arquivo) e de um byte nulo de folga. São gravados
 *          no campo `magic` de @ref zupt_archive_header_t e servem para
 *          reconhecer o arquivo e rejeitar versões incompatíveis de leitura.
 */
#define ZUPT_MAGIC_0  0x5A
/** @brief Segundo byte da assinatura do cabeçalho: `0x55` (`'U'`). */
#define ZUPT_MAGIC_1  0x55
/** @brief Terceiro byte da assinatura do cabeçalho: `0x50` (`'P'`). */
#define ZUPT_MAGIC_2  0x50
/** @brief Quarto byte da assinatura do cabeçalho: `0x54` (`'T'`). */
#define ZUPT_MAGIC_3  0x54
/** @brief Quinto byte da assinatura do cabeçalho: `0x1A` (controle ASCII `EOF`/substituto). */
#define ZUPT_MAGIC_4  0x1A
/** @brief Sexto byte da assinatura do cabeçalho: `0x00` (folga de terminador). */
#define ZUPT_MAGIC_5  0x00

/**
 * @def ZUPT_BLOCK_MAGIC_0
 * @brief Primeiro byte da assinatura de 2 bytes que precede cada bloco do arquivo: `0xBB`.
 * @details Combinado com @ref ZUPT_BLOCK_MAGIC_1 forma `0xBB 0x01`. Serve para
 *          delimitar e recuperar o início de um bloco durante a leitura, por
 *          exemplo ao reconstruir o índice a partir do corpo do arquivo, sem
 *          usar o rodapé.
 */
#define ZUPT_BLOCK_MAGIC_0 0xBB
/** @brief Segundo byte da assinatura de bloco: `0x01`. Ver @ref ZUPT_BLOCK_MAGIC_0. */
#define ZUPT_BLOCK_MAGIC_1 0x01

/**
 * @def ZUPT_MAX_PATH
 * @brief Comprimento máximo, em bytes, de um caminho armazenado nas estruturas (4096).
 * @details Usado como dimensão de `path` em @ref zupt_index_entry_t e de
 *          `keyfile` em @ref zupt_options_t. O valor inclui o terminador nulo:
 *          um caminho de exatamente `ZUPT_MAX_PATH` bytes não cabe com o
 *          terminador.
 */
#define ZUPT_MAX_PATH         4096
/**
 * @def ZUPT_MAX_FILES
 * @brief Limite superior de entradas de arquivo que a biblioteca pretende suportar (2.000.000).
 */
#define ZUPT_MAX_FILES        2000000
/**
 * @def ZUPT_DEFAULT_BLOCK_SZ
 * @brief Tamanho de bloco usado quando o chamador não escolhe um: 4 MiB.
 */
#define ZUPT_DEFAULT_BLOCK_SZ (4 * 1024 * 1024)
/**
 * @def ZUPT_MIN_BLOCK_SZ
 * @brief Menor tamanho de bloco aceito: 64 KiB.
 */
#define ZUPT_MIN_BLOCK_SZ     (64 * 1024)
/**
 * @def ZUPT_MAX_BLOCK_SZ
 * @brief Maior tamanho de bloco aceito: 256 MiB.
 * @details Os três limites acima são comparados ao campo `block_size` de
 *          @ref zupt_options_t antes de comprimar. Blocos maiores implicam mais
 *          memória no pico e menos redundância explorada entre blocos.
 */
#define ZUPT_MAX_BLOCK_SZ     (256 * 1024 * 1024)

/* Global flags */
/**
 * @def ZUPT_FLAG_ENCRYPTED
 * @brief Flag global: o conteúdo do arquivo está cifrado (bit 0).
 * @details Bit 0 do campo `global_flags` de @ref zupt_archive_header_t. Quando
 *          ligado, a leitura exige um @ref zupt_keyring_t válido (e, no modo
 *          pós-quântico, o cabeçalho de cifra híbrida).
 */
#define ZUPT_FLAG_ENCRYPTED    (1u << 0)
/**
 * @def ZUPT_FLAG_CKSUM_XXH64
 * @brief Flag reservada para soma de verificação XXH64; definida como zero.
 * @details Expande para `(0u << 5)`, ou seja, o valor resultante é `0`.
 *          Operações bitwise que usam esta macro para ligar um bit de
 *          `global_flags` não alteram o campo; o bit 5 portanto não é ocupado
 *          por esta macro.
 * @warning Registrado como achado de documentação (não corrigido): a forma
 *          provável era `(1u << 5)`. Ver @ref page-limitacoes.
 */
#define ZUPT_FLAG_CKSUM_XXH64  (0u << 5)
/**
 * @def ZUPT_FLAG_SOLID
 * @brief Flag global: arquivo em modo sólido, com blocos compartilhando contexto de compressão (bit 1).
 * @details Indica que o arquivo foi produzido por @ref zupt_compress_solid;
 *          nesse caso os blocos não são independentes quanto ao contexto do
 *          codec e precisam ser decodificados na ordem de gravação.
 */
#define ZUPT_FLAG_SOLID        (1u << 1)
/**
 * @def ZUPT_FLAG_MULTITHREADED
 * @brief Flag informativa: o arquivo foi produzido com compressão multinúcleo (bit 2).
 * @details Não altera a decodificação: um extrator serial consegue ler um
 *          arquivo com este bit ligado.
 */
#define ZUPT_FLAG_MULTITHREADED (1u << 2) /* Informational: archive was produced with MT */
/**
 * @def ZUPT_FLAG_PQ_HYBRID
 * @brief Flag global: cifra híbrida pós-quântica ML-KEM-768 + X25519 (bit 3).
 * @details Ligado quando a chave de sessão veio de
 *          @ref zupt_hybrid_encrypt_init ou @ref zupt_hybrid_encrypt_init_mem,
 *          e não de @ref zupt_derive_keys. Ver também
 *          @ref ZUPT_ENC_PQ_HYBRID.
 */
#define ZUPT_FLAG_PQ_HYBRID    (1u << 3) /* Post-quantum hybrid encryption */
/**
 * @def ZUPT_FLAG_FORMAT_STABLE
 * @brief Flag que marca o formato como congelado na v1.0 (bit 4).
 */
#define ZUPT_FLAG_FORMAT_STABLE (1u << 4) /* v1.0: format frozen */
/**
 * @def ZUPT_FLAG_DEDUP
 * @brief Flag global: deduplicação no nível de bloco habilitada (bit 7).
 * @details Quando ligada, blocos repetidos podem ser gravados como
 *          @ref ZUPT_BLOCK_DEDUP_REF em vez de uma cópia do payload.
 */
#define ZUPT_FLAG_DEDUP        (1u << 7) /* Block-level deduplication enabled */

/* Encryption types (stored in encryption header block) */
/**
 * @def ZUPT_ENC_PBKDF2
 * @brief Tipo de cifra por senha: PBKDF2-HMAC-SHA256 com AES-256-CTR + HMAC-SHA256 (`0x01`).
 * @details Valor gravado no campo de tipo do bloco de cabeçalho de cifra. As
 *          chaves são derivadas de senha e salt por @ref zupt_pbkdf2_sha256 e
 *          montadas em um @ref zupt_keyring_t por @ref zupt_derive_keys; o
 *          número de iterações é o de @ref ZUPT_KDF_ITERATIONS, salvo quando o
 *          arquivo grava valor diferente.
 */
#define ZUPT_ENC_PBKDF2     0x01  /* Password-based: PBKDF2 → AES-256-CTR + HMAC */
/**
 * @def ZUPT_ENC_PQ_HYBRID
 * @brief Tipo de cifra híbrida pós-quântica: KEM ML-KEM-768 + X25519 (`0x03`).
 * @details Valor gravado no campo de tipo do bloco de cabeçalho de cifra. A
 *          chave de sessão vem de uma chave compartilhada híbrida (ML-KEM-768
 *          sobre X25519) transportada no cabeçalho de cifra de 1137 bytes. Não
 *          há senha: o segredo é a posse da chave privada.
 * @see zupt_hybrid_keygen, zupt_hybrid_encrypt_init, zupt_hybrid_decrypt_init,
 *      ZUPT_FLAG_PQ_HYBRID
 */
#define ZUPT_ENC_PQ_HYBRID  0x03  /* ML-KEM-768 + X25519 hybrid KEM */

/**
 * @def ZUPT_BLOCK_DATA
 * @brief Tipo de bloco `0x00`: bloco de dados, com o payload de um arquivo ou de uma imagem.
 * @details É o tipo mais frequente do contêiner; os demais tipos descrevem
 *          metadados (índice, cabeçalho de cifra, referência de deduplicação).
 */
#define ZUPT_BLOCK_DATA       0x00
/**
 * @def ZUPT_BLOCK_INDEX
 * @brief Tipo de bloco `0x02`: bloco que contém o índice do arquivo.
 * @details Sua posição em disco é registrada em `index_offset` do rodapé,
 *          campo de @ref zupt_footer_t.
 */
#define ZUPT_BLOCK_INDEX      0x02
/**
 * @def ZUPT_BLOCK_ENC_HEADER
 * @brief Tipo de bloco (0x03) reservado ao cabeçalho de descriptografia.
 * @details Blocos de dados carregam um cabeçalho de 16 bytes em que este campo
 *          identifica o que o payload representa; este tipo guarda os
 *          parâmetros necessários para reconstituir a chave de sessão
 *          (salto, iterações da KDF, chave envelopada).
 */
#define ZUPT_BLOCK_ENC_HEADER 0x03
/**
 * @def ZUPT_BLOCK_DEDUP_REF
 * @brief Tipo de bloco (0x04) que referencia um bloco já gravado.
 * @details O payload é composto apenas por 8 bytes com o deslocamento, em
 *          disco, do bloco original — mecanismo de desduplicação.
 * @see ZUPT_DEDUP_MAX_ENTRIES
 */
#define ZUPT_BLOCK_DEDUP_REF  0x04  /* Dedup reference: payload = 8B offset of original block */
/**
 * @def ZUPT_BFLAG_ENCRYPTED
 * @brief Bit (1u &lt;&lt; 0) do campo `block_flags` do cabeçalho de um bloco.
 * @details Indica que o payload do bloco está cifrado. É independente dos
 *          flags globais do arquivo (@ref ZUPT_FLAG_ENCRYPTED): o bloco do
 *          cabeçalho de criptografia pode usar este bit ao transportar a
 *          chave de sessão envelopada.
 */
#define ZUPT_BFLAG_ENCRYPTED  (1u << 0)
/**
 * @def ZUPT_CODEC_STORE
 * @brief Identificador de codec (0x0000): dados armazenados sem compressão.
 * @details Usado quando o codec resultou em saída maior que a entrada.
 */
#define ZUPT_CODEC_STORE   0x0000
/**
 * @def ZUPT_CODEC_ZUPT_LZ
 * @brief Identificador de codec (0x0008): compressão LZ77 própria.
 */
#define ZUPT_CODEC_ZUPT_LZ 0x0008
/**
 * @def ZUPT_CODEC_ZUPT_LZH
 * @brief Identificador de codec (0x0009): LZ77 seguido de Huffman.
 */
#define ZUPT_CODEC_ZUPT_LZH 0x0009  /* LZ77 + Huffman */
/**
 * @def ZUPT_CODEC_ZUPT_LZHP
 * @brief Identificador de codec (0x000A): LZ77 + Huffman + predição de bytes.
 * @details O comentário de @ref ZUPT_CODEC_ZUPT_LZHP no cabeçalho o aponta
 *          como padrão da biblioteca.
 */
#define ZUPT_CODEC_ZUPT_LZHP 0x000A /* LZ77 + Huffman + Byte Prediction (default) */
/**
 * @def ZUPT_CODEC_VAPTVUPT
 * @brief Identificador de codec (0x0010): VaptVupt LZ com entropia ANS.
 */
#define ZUPT_CODEC_VAPTVUPT  0x0010 /* VAPTVUPT: VaptVupt LZ + ANS entropy codec */
/**
 * @def ZUPT_CODEC_AUTO
 * @brief Identificador de codec (0xFFFF): escolha automática pelo ambiente.
 * @details O comentário do cabeçalho resume a política a "VaptVupt se houver
 *          AVX2, senão LZHP". A função que resolveria essa escolha,
 *          @ref zupt_resolve_auto_codec, não possui definição em `src/`.
 */
#define ZUPT_CODEC_AUTO      0xFFFF /* Auto-detect: VaptVupt if AVX2, else LZHP */
/**
 * @def ZUPT_SALT_SIZE
 * @brief Tamanho do salto usado pela derivação de chave a partir de senha: 32 bytes.
 * @details É o tamanho lido/escrito por @ref zupt_encrypt_buffer e
 *          @ref zupt_decrypt_buffer e o esperado por
 *          @ref zupt_derive_keys. Aleatório por arquivo, gerado por
 *          @ref zupt_random_bytes.
 */
#define ZUPT_SALT_SIZE       32
/**
 * @def ZUPT_NONCE_SIZE
 * @brief Tamanho do vetor de não-repetição do AES-256-CTR: 16 bytes.
 */
#define ZUPT_NONCE_SIZE      16
/**
 * @def ZUPT_HMAC_SIZE
 * @brief Tamanho da tag HMAC-SHA256 que protege o payload cifrado: 32 bytes.
 */
#define ZUPT_HMAC_SIZE       32
/**
 * @def ZUPT_AES_KEY_SIZE
 * @brief Tamanho da chave AES usada pela biblioteca: 32 bytes (AES-256).
 */
#define ZUPT_AES_KEY_SIZE    32
/**
 * @def ZUPT_KDF_ITERATIONS
 * @brief Iterações da PBKDF2-HMAC-SHA256 aplicada a senhas: 600000.
 * @details Custo de derivar uma chave de senha: o número foi escolhido para
 *          dificultar ataques offline; qualquer mudança é incompatível com
 *          arquivos já gravados.
 */
#define ZUPT_KDF_ITERATIONS  600000
/**
 * @enum   zupt_error_t
 * @brief  Códigos de retorno usados pela maioria das funções da biblioteca.
 * @details Todos os erros são negativos; @ref ZUPT_OK vale zero. A tabela
 *          abaixo resume o significado de cada constante.
 *
 *          | Constante | Valor | Significado |
 *          |---|---|---|
 *          | ZUPT_OK | 0 | Operação concluída com sucesso. |
 *          | ZUPT_ERR_IO | -1 | Falha de E/S: abrir, ler, escrever ou obter tamanho. |
 *          | ZUPT_ERR_CORRUPT | -2 | Estrutura interna inconsistente ao ler o arquivo. |
 *          | ZUPT_ERR_BAD_MAGIC | -3 | Magic/assinatura ausente ou diferente do esperado. |
 *          | ZUPT_ERR_BAD_VERSION | -4 | Versão de formato (arquivo, chave ou envelope) não suportada. |
 *          | ZUPT_ERR_BAD_CHECKSUM | -5 | Soma de verificação não confere. |
 *          | ZUPT_ERR_NOMEM | -6 | Falha de alocação de memória. |
 *          | ZUPT_ERR_OVERFLOW | -7 | Tamanho/contagem excede o máximo suportado. |
 *          | ZUPT_ERR_INVALID | -8 | Argumento, tamanho ou estado inválido. |
 *          | ZUPT_ERR_NOT_FOUND | -9 | Item procurado não existe (por exemplo uma chave). |
 *          | ZUPT_ERR_UNSUPPORTED | -10 | Operação, codec ou parâmetro não suportado nesta build. |
 *          | ZUPT_ERR_AUTH_FAIL | -11 | Autenticação falhou: MAC/envelope não validou. |
 *
 * @note    Nem toda função devolui @ref zupt_error_t; as que alocam memória
 *          devolvem ponteiro e indicam falha com `NULL`, e as de verificação
 *          criptográfica devolvem inteiro não-nulo em caso de falha.
 */

typedef enum {
    /** Sucesso. Único valor não negativo do enumerado. */
    ZUPT_OK = 0,
    /** Falha de leitura ou escrita em disco. */
    ZUPT_ERR_IO = -1,
    /** Estrutura interna do contêiner inconsistente. */
    ZUPT_ERR_CORRUPT = -2,
    /** Magic de arquivo ou de bloco inválido. */
    ZUPT_ERR_BAD_MAGIC = -3,
    /** Versão de formato não suportada. */
    ZUPT_ERR_BAD_VERSION = -4,
    /** Checksum divergente do conteúdo lido. */
    ZUPT_ERR_BAD_CHECKSUM = -5,
    /** Alocação de memória falhou. */
    ZUPT_ERR_NOMEM = -6,
    /** Saída maior que a capacidade informada pelo chamador. */
    ZUPT_ERR_OVERFLOW = -7,
    /** Argumento inválido, por exemplo ponteiro `NULL` onde não é aceito. */
    ZUPT_ERR_INVALID = -8,
    /** Entrada ou arquivo solicitado não existe. */
    ZUPT_ERR_NOT_FOUND = -9,
    /** Recurso solicitado não implementado nesta versão. */
    ZUPT_ERR_UNSUPPORTED = -10,
    /** Autenticação falhou: o HMAC do bloco não confere. */
    ZUPT_ERR_AUTH_FAIL = -11,
} zupt_error_t;


/* ─── On-disk (packed LE) ─── */
/**
 * @struct zupt_archive_header_t
 * @brief  Cabeçalho fixo de 64 bytes no início de todo arquivo da biblioteca.
 * @details Estrutura empacotada sem alinhamento (o pragma `pack(push,1)`),
 *          pensada para espelhar byte a byte o que está em disco. Campos
 *          numéricos multibyte são little-endian no arquivo: a escrita/leitura
 *          correta em hosts big-endian depende dos helpers
 *          @ref zupt_le16_put / @ref zupt_le32_put / @ref zupt_le64_put e seus
 *          equivalentes de leitura, e não de copiar este struct como um bloco.
 * @note    O tamanho esperado é 64 bytes por construção do empacotamento.
 */
#pragma pack(push, 1)
typedef struct {
    /** Magic do arquivo: os bytes de ::ZUPT_MAGIC_0 a ::ZUPT_MAGIC_5. */
    uint8_t  magic[6];
    /** Versão do formato, separada em byte alto e byte baixo. */
    uint8_t  version_major, /**< Byte alto da versão do formato. */
                 version_minor; /**< Byte baixo da versão do formato. */
    /** Flags globais, entre ::ZUPT_FLAG_ENCRYPTED e ::ZUPT_FLAG_DISK_IMAGE. */
    uint32_t global_flags;
    /** Timestamp Unix de criação, em segundos. */
    uint64_t creation_time;
    /** Identificador de 16 bytes da instância de arquivo. */
    uint8_t  archive_id[16];
    /** Deslocamento do cabeçalho de criptografia, ou 0 quando não criptografado. */
    uint64_t encryption_header_off;
    /** Deslocamento do comentário do arquivo, ou 0 quando não há comentário. */
    uint64_t comment_offset;
    /** Zona reservada, sempre zero na escrita. */
    uint8_t  reserved[12];
} zupt_archive_header_t; /* 64 bytes */

/**
 * @struct zupt_footer_t
 * @brief  Rodapé fixo de 32 bytes no fim do arquivo, usado para localizar o índice.
 * @details Empacotado como o cabeçalho. A leitura típica de um arquivo começa
 *          aqui: o leitor vai ao fim, confere `footer_magic`, usa
 *          `index_offset` para reler o bloco de índice e então compara
 *          `archive_checksum`.
 */
typedef struct {
    /** Deslocamento, em bytes a partir do início do arquivo, do bloco de índice. */
    uint64_t index_offset;
    /** Total de blocos de dados registrados no arquivo. */
    uint64_t total_blocks;
    /** CRC-32 calculado sobre todo o arquivo, exceto os 4 bytes deste campo. */
    uint64_t archive_checksum;
    /** Magic do rodapé: a sequência ASCII "ZEND". */
    uint8_t  footer_magic[4]; /* "ZEND" */
    /** Versão do rodapé, no formato `(major << 8) | minor`. */
    uint32_t footer_version;
} zupt_footer_t; /* 32 bytes */
#pragma pack(pop)

/* ─── In-memory ─── */
/**
 * @struct zupt_index_entry_t
 * @brief  Entrada da tabela de índice: um arquivo (ou imagem) armazenado.
 * @details Representação em memória; não corresponde a um layout em disco. O
 *          índice físico é o bloco @ref ZUPT_BLOCK_INDEX, gravado em formato
 *          próprio e lido a partir de @ref zupt_footer_t::index_offset.
 */
typedef struct {
    char path[ZUPT_MAX_PATH]; /**< Caminho lógico do arquivo na entrada. */
    uint64_t uncompressed_size, /**< Tamanho original do arquivo, em bytes. */
                 compressed_size; /**< Tamanho do arquivo após compressão, em bytes. */
    uint64_t modification_time, /**< Timestamp Unix da última modificação. */
                 content_hash; /**< Hash de conteúdo usado em deduplicação. */
    uint64_t first_block_offset; /**< Deslocamento do primeiro bloco de dados do arquivo. */
    uint32_t block_count, /**< Quantidade de blocos de dados desta entrada. */
                 attributes; /**< Atributos da entrada; a biblioteca não os interpreta. */
} zupt_index_entry_t;

/**
 * @struct zupt_block_t
 * @brief  Bloco lido ou a ser gravado: cabeçalho de bloco + payload em memória.
 * @details `payload` aponta para o conteúdo comprimido (e possivelmente cifrado)
 *          tal como está em disco. A decodificação é feita por
 *          @ref decompress_block, que trata cifra e codec.
 */
typedef struct {
    uint8_t block_type; /**< Tipo do bloco: ::ZUPT_BLOCK_DATA, ::ZUPT_BLOCK_INDEX, ::ZUPT_BLOCK_ENC_HEADER ou ::ZUPT_BLOCK_DEDUP_REF. */
    uint16_t codec_id, /**< Codec usado neste bloco, um dos códigos `ZUPT_CODEC_*`. */
                 block_flags; /**< Flags de bloco; hoje o único bit definido é ::ZUPT_BFLAG_ENCRYPTED. */
    uint64_t uncompressed_size, /**< Tamanho do bloco descomprimido, em bytes. */
                 compressed_size, /**< Tamanho do bloco como gravado, em bytes. */
                 checksum; /**< Checksum de 32 bits do conteúdo descomprimido. */
    uint8_t *payload; /**< Ponteiro para o conteúdo do bloco, ou NULL quando não carregado. */
} zupt_block_t;

/* Buffer canary for keyring overflow detection */
/**
 * @def ZUPT_CANARY
 * @brief Padrão mágico usado como canary de borda do @ref zupt_keyring_t.
 * @details Escrito no início e no fim do contexto de chaves. Qualquer escrita
 *          fora dos limites que toque um dos dois valores é detectada por
 *          @ref zupt_keyring_check.
 */
#define ZUPT_CANARY 0xDEADCAFEBABEFACEULL

/**
 * @struct zupt_keyring_t
 * @brief  Material de chave de sessão: chaves AES e MAC, salt, nonce base e contadores.
 * @details É o estado que @ref zupt_encrypt_buffer e @ref zupt_decrypt_buffer
 *          usam para cifrar e autenticar um bloco. Pode vir de senha
 *          (@ref zupt_derive_keys) ou de um KEM híbrido
 *          (@ref zupt_hybrid_encrypt_init / @ref zupt_hybrid_decrypt_init).
 *
 *          As duas palavras `canary_head`/`canary_tail` delimitam o struct e
 *          valem @ref ZUPT_CANARY depois de @ref zupt_keyring_init.
 * @note    Contém segredos: não deve ser copiado para memória trocável. Use
 *          @ref zupt_mlock_keys para tentar fixá-lo em RAM e
 *          @ref zupt_secure_wipe antes de descartá-lo.
 */
typedef struct {
    uint64_t canary_head; /**< Canary de inicialização, deve ser igual a ::ZUPT_CANARY. */
    uint8_t enc_key[ZUPT_AES_KEY_SIZE]; /**< Chave AES-256-CTR. */
    uint8_t mac_key[ZUPT_HMAC_SIZE]; /**< Chave de 32 bytes para o HMAC-SHA256 da autenticação. */
    uint8_t salt[ZUPT_SALT_SIZE]; /**< Salt de 32 bytes usado no PBKDF2. */
    uint8_t base_nonce[ZUPT_NONCE_SIZE]; /**< Nonce base de 16 bytes combinado com o número do bloco. */
    uint32_t iterations; /**< Iterações de PBKDF2 usadas na derivação, registrado no arquivo. */
    int active; /**< 1 quando a chave está pronta para uso. É posto a 1 pelas
                  funções de geração/importação de chave; nenhum código em
                  `src/` o recoloca a 0. */
    uint64_t canary_tail; /**< Canary final, deve ser igual a ::ZUPT_CANARY. */
} zupt_keyring_t;

/* Check keyring canaries — abort on buffer overflow */
/**
 * @brief Monta um anel de chaves vazio, com os dois canary ligados.
 * @details Zera o struct inteiro byte a byte através de um ponteiro
 *          `volatile`, para que o compilador não elimine a limpeza, e então
 *          escreve @ref ZUPT_CANARY em `canary_head` e `canary_tail`.
 * @param[out] kr Anel de chaves a inicializar.
 * @post `canary_head` e `canary_tail` valem @ref ZUPT_CANARY e todo o restante
 *       é zero.
 * @see zupt_keyring_check()
 */
static inline void zupt_keyring_init(zupt_keyring_t *kr) {
    volatile uint8_t *p = (volatile uint8_t *)kr;
    for (size_t i = 0; i < sizeof(*kr); i++) p[i] = 0;
    kr->canary_head = ZUPT_CANARY;
    kr->canary_tail = ZUPT_CANARY;
}
/**
 * @brief Verifica os canary do anel de chaves e termina o processo se foram corrompidos.
 * @details Se `canary_head` ou `canary_tail` divergir de @ref ZUPT_CANARY,
 *          imprime uma mensagem em `stderr` e termina o processo imediatamente
 *          com status 127. Não retorna ao chamador nesse caso.
 * @param[in] kr Anel de chaves a auditar.
 * @warning Esta função pode encerrar o processo de quem a chamou. O comentário
 *          do código diz "Use exit(127)", mas a chamada real é `_exit(127)` —
 *          que encerra sem correr `atexit` nem esvaziar `stdio`, de modo que
 *          um `fprintf` anterior em `stdout` pode se perder. `_exit` é
 *          declarada por `<unistd.h>`, incluído apenas no ramo não-Windows
 *          deste cabeçalho (linha 104); o ramo Windows (`<windows.h>` e
 *          `<direct.h>`) não inclui cabeçalho que a declare.
 * @see zupt_keyring_init(), ZUPT_CANARY, @ref page-limitacoes
 */
static inline void zupt_keyring_check(const zupt_keyring_t *kr) {
    if (kr->canary_head != ZUPT_CANARY || kr->canary_tail != ZUPT_CANARY) {
        fprintf(stderr, "FATAL: keyring buffer overflow detected (canary corrupted)\n");
        /* Use exit(127) instead of abort() to avoid needing <stdlib.h> */
        _exit(127);
    }
}

/**
 * @struct zupt_filelist_t
 * @brief  Lista dinâmica de pares (caminho em disco, caminho no arquivo).
 * @details Vetor de strings `paths` e `arc_paths` com `count` entradas
 *          ocupadas e `capacity` de espaço alocado. Gerado por
 *          @ref zupt_collect_files / @ref zupt_filelist_add e liberado por
 *          @ref zupt_filelist_free.
 */
typedef struct {
    char **paths, /**< Vetor de caminhos no sistema de arquivos. */
                 **arc_paths; /**< Vetor de caminhos arquivados (relativos), alinhado com paths. */
    int count, /**< Quantidade de itens válidos nos vetores. */
                 capacity; /**< Capacidade alocada dos vetores. */
} zupt_filelist_t;

/**
 * @struct zupt_options_t
 * @brief  Parâmetros de uma operação de compressão/extração.
 * @details Uma única estrutura cobre compressão, extração, listagem e teste.
 *          Nem todos os campos são lidos por todas as operações (por exemplo
 *          `password` só tem efeito na derivação de chave por senha).
 * @note    `password` tem capacidade fixa de 256 bytes, incluindo o
 *          terminador nulo: senhas maiores são truncadas pelo chamador, e esse
 *          truncamento altera a chave derivada.
 */
typedef struct {
    int level; /**< Nível de compressão, 1 a 9. */
    uint32_t block_size; /**< Tamanho de bloco em KB. */
    uint16_t codec_id; /**< Codec principal, um dos códigos `ZUPT_CODEC_*`. */
    int verbose, /**< 1 para saída detalhada; a biblioteca em si não imprime. */
                 encrypt, /**< 1 para criptografar o arquivo. */
                 quiet, /**< 1 para suprimir mensagens; reservado, sem efeito na biblioteca. */
                 solid, /**< 1 para modo sólido (dicionário compartilhado); reservado. */
                 threads; /**< Número de threads desejado; reservado, o processamento é sequencial. */
    int pq_mode; /**< 1 para modo híbrido pós-quântico, 0 para PBKDF2 puro. */
    int dedup; /**< 1 para habilitar deduplicação em nível de bloco. */
    char password[256]; /**< Senha usada para derivar as chaves. */
    char keyfile[ZUPT_MAX_PATH]; /**< Caminho de arquivo de chaves .zupt-key. */
    zupt_keyring_t keyring; /**< Chaveiro derivado, preenchido por ::zupt_derive_keys(). */
} zupt_options_t;

/* ═══════════════════════════════════════════════════════════════════
 * PORTABLE LITTLE-ENDIAN SERIALIZATION
 *
 * All multi-byte fields in the on-disk format are stored as LE.
 * These helpers ensure correct behaviour on both LE and BE hosts.
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * @brief Grava `v` como 2 bytes little-endian em `p`.
 * @param[out] p Destino de exatamente 2 bytes graváveis.
 * @param[in]  v Valor de 16 bits a serializar.
 * @post `p[0]` contém o byte menos significativo e `p[1]` o mais significativo.
 * @note Não depende da endianidade do host: os bytes são extraídos por
 *       deslocamento e máscara.
 */
static inline void zupt_le16_put(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
}
/**
 * @brief Grava `v` como 4 bytes little-endian em `p`.
 * @param[out] p Destino de exatamente 4 bytes graváveis.
 * @param[in]  v Valor de 32 bits a serializar.
 * @post `p[0]` é o byte menos significativo, `p[3]` o mais significativo.
 */
static inline void zupt_le32_put(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}
/**
 * @brief Grava `v` como 8 bytes little-endian em `p`.
 * @param[out] p Destino de exatamente 8 bytes graváveis.
 * @param[in]  v Valor de 64 bits a serializar.
 * @post `p[0]` é o byte menos significativo, `p[7]` o mais significativo.
 */
static inline void zupt_le64_put(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) { p[i] = (uint8_t)(v & 0xFF); v >>= 8; }
}
/**
 * @brief Lê 2 bytes little-endian de `p` como `uint16_t`.
 * @param[in] p Leitura de exatamente 2 bytes.
 * @return Valor reconstruído, com `p[0]` como byte menos significativo.
 */
static inline uint16_t zupt_le16_get(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}
/**
 * @brief Lê 4 bytes little-endian de `p` como `uint32_t`.
 * @param[in] p Leitura de exatamente 4 bytes.
 * @return Valor reconstruído, com `p[0]` como byte menos significativo.
 */
static inline uint32_t zupt_le32_get(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
/**
 * @brief Lê 8 bytes little-endian de `p` como `uint64_t`.
 * @param[in] p Leitura de exatamente 8 bytes.
 * @return Valor reconstruído, com `p[0]` como byte menos significativo.
 */
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
 * @brief Zera `len` bytes de `ptr`, tentando impedir que o compilador elimine a escrita.
 * @details O objetivo é apagar material de chave antes de liberar a memória.
 *          Uma simples `memset` pode ser otimizada fora do código quando o
 *          buffer não é lido depois; as variantes escolhidas impedem isso.
 *          Ramais de plataforma:
 *          - Windows (`_WIN32`): `SecureZeroMemory`;
 *          - glibc 2.25 ou mais nova: `explicit_bzero` (declaração local);
 *          - FreeBSD/OpenBSD: `explicit_bzero` (declaração local);
 *          - demais plataformas: laço byte a byte através de um ponteiro
 *            `volatile uint8_t *`.
 * @param[out] ptr Início da região a zerar.
 * @param[in]  len Número de bytes a zerar.
 * @post Todos os `len` bytes de `ptr` valem 0.
 * @note A portabilidade entre as quatro variantes não é verificada neste
 *       repositório: não há compilação/CI para as plataformas não-Linux.
 * @see zupt_mlock_keys()
 */
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
 * @brief Determina se `path` aponta para um arquivo regular.
 * @details Usado para pular links simbólicos, dispositivos, FIFOs e sockets
 *          durante a coleta de arquivos, evitando ler algo que não é um
 *          conteúdo arquivável.
 *          Ramais de plataforma:
 *          - Windows (`_WIN32`): `GetFileAttributesA` e rejeição de
 *            `FILE_ATTRIBUTE_DIRECTORY`, `FILE_ATTRIBUTE_DEVICE` e
 *            `FILE_ATTRIBUTE_REPARSE_POINT`;
 *          - demais: `lstat` (não segue o link) e `S_ISREG`.
 * @param[in] path Caminho a testar.
 * @return 1 quando o alvo é um arquivo regular; 0 quando não é, ou quando a
 *         consulta de atributos/`lstat` falha.
 * @note A consulta não segue links simbólicos em nenhum dos dois ramos, então
 *       um link para um arquivo regular devolve 0.
 */
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
 * @brief Comprime vários arquivos em um arquivo único em modo sólido.
 * @details No modo sólido os blocos dos diversos arquivos compartilham o mesmo
 *          contexto do codec, o que costuma reduzir o tamanho quando há
 *          arquivos parecidos entre si. Em contrapartida os blocos deixam de
 *          ser independentes: extrair um item exige reproduzir a decompressão
 *          dos anteriores.
 * @param[in]     out  Caminho do arquivo de saída a criar.
 * @param[in]     arc  Vetor de `n` caminhos lógicos (como ficam gravados).
 * @param[in]     disk Vetor de `n` caminhos reais em disco.
 * @param[in]     n    Número de pares; `arc` e `disk` devem ter `n` elementos.
 * @param[in,out] opts Opções; o campo `keyring` é montado quando há cifra.
 * @return @ref ZUPT_OK em sucesso; código negativo em falha.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho
 *       mas não possui definição em `src/`.
 * @see ZUPT_FLAG_SOLID, zupt_compress_files()
 */
zupt_error_t zupt_compress_solid(const char *out, const char **arc, const char **disk, int n, zupt_options_t *opts);

/* ─── SHA-256 ─── */
/**
 * @struct zupt_sha256_ctx
 * @brief  Estado incremental de uma computação SHA-256.
 * @details `state` guarda as 8 palavras de 32 bits do estado de trabalho;
 *          `count` acumula o total de bytes absorvidos; `buf` guarda os bytes
 *          ainda não processados do bloco corrente. Usado na sequência
 *          @ref zupt_sha256_init → @ref zupt_sha256_update →
 *          @ref zupt_sha256_final. Implementado em src/zupt_sha256.c.
 */
typedef struct {
    /** Vetor de estado SHA-256, oito palavras de 32 bits (H0..H7). */
    uint32_t state[8];
    /** Quantidade total de bytes processados. */
    uint64_t count;
    /** Buffer parcial de até 64 bytes, um bloco do SHA-256. */
    uint8_t buf[64];
} zupt_sha256_ctx;
/**
 * @brief Prepara o contexto para computar um novo digest SHA-256.
 * @param[out] c Contexto a inicializar.
 * @post O estado de trabalho recebe o vetor inicial do SHA-256, `count` vale 0
 *       e o buffer de bloco corrente é zerado.
 */
void zupt_sha256_init(zupt_sha256_ctx *c);
/**
 * @brief Absorve mais `n` bytes na computação incremental do digest.
 * @param[in,out] c Contexto já inicializado.
 * @param[in]     d Bytes a absorver (pode ser NULL apenas se `n` for 0).
 * @param[in]     n Número de bytes a processar.
 * @note Blocos completos de 64 bytes são comprimidos imediatamente; a parte
 *       restante fica retida em `c->buf`.
 */
void zupt_sha256_update(zupt_sha256_ctx *c, const uint8_t *d, size_t n);
/**
 * @brief Aplica o padding, comprime o último bloco e produz o digest final.
 * @param[in,out] c Contexto a finalizar.
 * @param[out]    h Destino de exatamente 32 bytes do digest.
 * @note Depois desta chamada o contexto não deve ser reutilizado sem nova
 *       @ref zupt_sha256_init.
 */
void zupt_sha256_final(zupt_sha256_ctx *c, uint8_t h[32]);
/**
 * @brief Calcula o digest SHA-256 de `n` bytes em uma única chamada.
 * @param[in]  d Dados a resumir.
 * @param[in]  n Número de bytes.
 * @param[out] h Destino de exatamente 32 bytes do digest.
 * @see zupt_sha256_init(), zupt_sha256_update(), zupt_sha256_final()
 */
void zupt_sha256(const uint8_t *d, size_t n, uint8_t h[32]);

/* ─── AES-256 ─── */
/**
 * @struct zupt_aes256_ctx
 * @brief  Round keys expandidas para AES-256.
 * @details `rk` contém as 60 palavras de 32 bits do expandimento de chave do
 *          AES-256 (15 rodadas × 4 palavras, cobrindo 14 rodadas). A
 *          expansão é feita por @ref zupt_aes256_init.
 * @note Só existe expansão para cifrar: a biblioteca usa o AES apenas no modo
 *       CTR (@ref zupt_aes256_ctr), que requer somente a primitiva de
 *       cifra de bloco. Não há expansão para decifrar.
 * @see src/zupt_aes256.c
 */
typedef struct {
    /** Rodadas de chave: 15 chaves de rodada de 4 colunas de 32 bits, com espaço de sobra. */
    uint32_t rk[60];
} zupt_aes256_ctx;
/**
 * @brief Expande uma chave de 32 bytes para as 60 round keys do AES-256.
 * @details As 8 palavras iniciais são montadas a partir dos bytes da chave na
 *          ordem mais-significativo-primeiro dentro de cada palavra. As demais
 *          são geradas pela recursão do AES-256, aplicando S-box + RCON a cada
 *          8 palavras e S-box adicional na posição `i % 8 == 4`.
 * @param[out] c   Contexto que recebe as round keys (`rk[0..59]` é escrito).
 * @param[in]  key Chave de 32 bytes legíveis.
 * @post `c->rk[0..59]` fica inicializado e é derivado apenas de `key`.
 * @see zupt_aes256_encrypt_block, zupt_aes256_ctr
 */
void zupt_aes256_init(zupt_aes256_ctx *c, const uint8_t key[32]);
/**
 * @brief Cifra um único bloco de 16 bytes com as round keys já expandidas.
 * @details É a primitiva ECB de um bloco: não há encadeamento, contador ou IV
 *          aqui. Serve de motor para @ref zupt_aes256_ctr.
 *          Duas implementações coexistem e a escolha é feita em tempo de
 *          execução: quando compilado para x86/x86-64 com GCC/Clang e sem
 *          `ZUPT_FORCE_PORTABLE_AES`, e `__builtin_cpu_supports("aes")` é
 *          verdadeiro, usa-se AES-NI; nos demais casos o caminho portátil em C.
 * @param[in]  c   Round keys de @ref zupt_aes256_init.
 * @param[in]  in  Bloco de entrada, 16 bytes legíveis.
 * @param[out] out Bloco cifrado, 16 bytes graváveis.
 * @pre `in` e `out` devem ser disjuntos, conforme a cláusula `\separated` da
 *      anotação ACSL adjunta.
 * @post Os 16 bytes de `out` ficam inicializados.
 */
void zupt_aes256_encrypt_block(const zupt_aes256_ctx *c, const uint8_t in[16], uint8_t out[16]);

/* ─── Crypto ops ─── */
/**
 * @name Operações criptográficas de alto nível
 *
 * @{ */

/**
 * @brief  Calcula HMAC-SHA256 (RFC 2104).
 * @param[in]  key  Chave do MAC, de `klen` bytes legíveis.
 * @param[in]  klen Comprimento da chave, em bytes; acima de 64 a chave é
 *                  pré-hashed com SHA-256 antes de montar os pads.
 * @param[in]  data Mensagem autenticada, de `dlen` bytes legíveis.
 * @param[in]  dlen Comprimento da mensagem, em bytes.
 * @param[out] mac  Destino de exatamente 32 bytes do MAC.
 * @post Os 32 bytes de `mac` ficam inicializados.
 * @note Implementada em `src/zupt_crypto.c`, que detalha a montagem dos pads
 *       e a limpeza dos temporários.
 * @see zupt_sha256, zupt_pbkdf2_sha256, zupt_encrypt_buffer
 */
void zupt_hmac_sha256(const uint8_t *key, size_t klen, const uint8_t *data, size_t dlen, uint8_t mac[32]);

/**
 * @brief  Deriva chave a partir de senha com PBKDF2-HMAC-SHA256 (RFC 2898).
 * @param[in]  pw     Senha (bytes da senha em claro).
 * @param[in]  pwlen  Comprimento da senha, em bytes.
 * @param[in]  salt   Salt, de `slen` bytes legíveis.
 * @param[in]  slen   Comprimento do salt, em bytes.
 * @param[in]  iterations Número de iterações (mínimo 1).
 * @param[out] output     Saída da derivação, `olen` bytes graváveis.
 * @param[in]  olen   Tamanho desejado da chave derivada, em bytes.
 * @note `src/zupt_crypto.c` limita o salt efetivo a 252 bytes por causa de um
 *       buffer em pilha; o uso da biblioteca sempre passa
 *       @ref ZUPT_SALT_SIZE (32), então o limite é uma rede de segurança.
 * @see ZUPT_KDF_ITERATIONS, zupt_derive_keys
 */
void zupt_pbkdf2_sha256(const uint8_t *pw, size_t pwlen, const uint8_t *salt, size_t slen, uint32_t iter, uint8_t *out, size_t olen);

/**
 * @brief  Cifra (ou decifra) `len` bytes em modo AES-256-CTR.
 * @details CTR gera keystream cifrando um contador; a mesma função serve para
 *          cifrar e decifrar. O contador inicial é uma cópia dos 16 bytes de
 *          `nonce` e é incrementado em big-endian apenas nos bytes 8..15.
 * @param[in]  key   Chave AES-256 (32 bytes legíveis).
 * @param[in]  nonce Bloco de contagem inicial (16 bytes legíveis); deve ser
 *                   único por par (chave, fluxo).
 * @param[in]  in    Dados de entrada, `len` bytes legíveis.
 * @param[out] out   Dados de saída, `len` bytes graváveis.
 * @param[in]  len   Comprimento dos dados, em bytes.
 * @pre `in` e `out` são disjuntos (cláusula `\separated` da anotação ACSL):
 *      cifra em lugar não está no contrato.
 * @note Sob `-DZUPT_USE_JASMIN` existe um dispatch adicional em tempo de
 *       execução para as primitivas assembly, condicionado a `zupt_cpu`
 *       (declarado em `include/zupt_cpuid.h`). Ver `src/zupt_crypto.c`.
 * @see zupt_aes256_init, zupt_aes256_encrypt_block, zupt_encrypt_buffer
 */
void zupt_aes256_ctr(const uint8_t key[32], const uint8_t nonce[16], const uint8_t *in, uint8_t *out, size_t len);

/**
 * @brief  Monta um anel de chaves a partir de senha, salt e nonce base.
 * @details Deriva 64 bytes com @ref zupt_pbkdf2_sha256 sobre a senha (comprida
 *          por `strlen`), o salt e `iterations`, e divide o material resultante
 *          em `enc_key` (bytes 0..31) e `mac_key` (bytes 32..63). Copia `salt`
 *          e `nonce` para o anel, grava `iterations` e liga `active`.
 *          O material intermediário em pilha é limpo com @ref zupt_secure_wipe
 *          e as duas chaves são passadas a @ref zupt_mlock_keys.
 * @param[out] kr   Anel de chaves a montar.
 * @param[in]  pw   Senha de derivação, terminada em nulo; o comprimento usado é
 *                  o de `strlen(pw)`.
 * @param[in]  salt Salt de 32 bytes legíveis (deve coincidir com o gravado no
 *                   cabeçalho de cifra).
 * @param[in]  nonce Nonce base de 16 bytes legíveis.
 * @param[in]  iterations Número de iterações de PBKDF2 a usar (ver
 *                  @ref ZUPT_KDF_ITERATIONS).
 * @post `kr->active` vale 1 e os campos de chave, salt, nonce e iterações estão
 *       preenchidos.
 * @warning Senha maior que a capacidade de @ref zupt_options_t (campo `password`) é
 *          truncada pelo chamador antes desta chamada, o que muda a chave.
 * @note Os canários são reescritos por esta função, de modo que ela não
 *       detecta uma corrupção anterior do anel.
 * @see ZUPT_ENC_PBKDF2, zupt_keyring_init, zupt_secure_wipe
 */
void zupt_derive_keys(zupt_keyring_t *kr, const char *pw, const uint8_t salt[32], const uint8_t nonce[16], uint32_t iter);

/**
 * @brief  Cifra um payload e produz o envelope Encrypt-then-MAC.
 * @details Formato do envelope devolvido, que é o que vai ao disco:
 *          `[16 bytes de nonce do bloco][plen bytes de texto cifrado]
 *          [32 bytes de HMAC-SHA256]`. O nonce do bloco é o
 *          @ref zupt_keyring_t (campo `base_nonce`) com seus 8 bytes menos
 *          significativos XOR `seq` em little-endian; o HMAC, com
 *          `mac_key`, cobre `nonce || texto cifrado`.
 * @param[in]  kr   Anel de chaves ativo (`enc_key`, `mac_key` e `base_nonce`
 *                  válidos; o contrato ACSL exige `active == 1`).
 * @param[in]  plain Dados em claro, `plen` bytes legíveis.
 * @param[in]  plen Comprimento dos dados em claro, em bytes; `plen == 0` gera
 *                  um envelope de 48 bytes.
 * @param[in]  block_seq Sequência do bloco, que diferencia o nonce entre blocos do
 *                  mesmo arquivo. Não repita o par (chave, `seq`): a keystream
 *                  seria reaproveitada.
 * @param[out] olen Recebe o tamanho total do envelope, igual a
 *                  `16 + plen + 32`.
 * @return Buffer recém-alocado com o envelope, ou `NULL` se a alocação falhar.
 * @retval !=NULL Pacote de `*olen` bytes; o chamador é dono da memória.
 * @retval NULL   Falha de alocação; neste caso `*olen` já foi escrita.
 * @note Quem recebe o buffer é responsável por liberá-lo.
 * @see zupt_decrypt_buffer, ZUPT_BFLAG_ENCRYPTED, zupt_aes256_ctr
 */
uint8_t *zupt_encrypt_buffer(const zupt_keyring_t *kr, const uint8_t *plain, size_t plen, uint64_t seq, size_t *olen);

/**
 * @brief  Confere o MAC e decifra um envelope produzido por @ref
 *         zupt_encrypt_buffer.
 * @details Opera sobre o envelope `[nonce][texto cifrado][HMAC]`: o HMAC é
 *          recomputado com `mac_key` e comparado, o nonce do envelope é
 *          conferido contra o esperado para `seq`, e só então o texto cifrado
 *          é decifrado para um buffer recém-alocado.
 * @param[in]  kr      Anel de chaves ativo.
 * @param[in]  pkg     Envelope, `pkglen` bytes legíveis.
 * @param[in]  pkglen  Comprimento do envelope, em bytes.
 * @param[in]  block_seq Sequência do bloco, a mesma usada na cifra; participa da
 *                    conferência do nonce.
 * @param[out] olen    Recebe o comprimento dos dados em claro.
 * @return Buffer recém-alocado com os dados em claro, ou `NULL` quando o MAC
 *         não valida, o nonce não confere, `pkglen` é inconsistente ou a
 *         alocação falha.
 * @note Um retorno `NULL` agrupa causas distintas (autenticação, formato e
 *       memória); não há como distingui-las por esta interface.
 * @see zupt_encrypt_buffer, ZUPT_ERR_AUTH_FAIL
 */
uint8_t *zupt_decrypt_buffer(const zupt_keyring_t *kr, const uint8_t *pkg, size_t pkglen, uint64_t seq, size_t *olen);

/**
 * @brief  Preenche `buf` com bytes de fonte aleatória criptograficamente segura.
 * @details Ramais de plataforma (em `src/zupt_crypto.c`):
 *          - Windows (`_WIN32`): `RtlGenRandom` (`SystemFunction036`) carregado
 *            via `LoadLibraryA`;
 *          - Linux: tenta `getrandom(2)` quando `SYS_getrandom` existe;
 *          - demais sistemas / reserva: leitura de `/dev/urandom`.
 * @param[out] buf Destino de `len` bytes graváveis.
 * @param[in]  len Quantidade de bytes a gerar.
 * @warning A função <b>não</b> devolve erro: quando nenhuma fonte está
 *          disponível, imprime mensagem fatal em `stderr` e encerra o processo
 *          com `exit(1)`. Não há tratamento de erro recuperável.
 * @see zupt_derive_keys, zupt_hybrid_keygen
 */
void zupt_random_bytes(uint8_t *buf, size_t len);

/**@}*/

/* ─── Memory locking for key material ─── */
/**
 * @brief  Tenta fixar em RAM um intervalo que contém material de chave.
 * @details Objetivo é evitar que segredos sejam escritos em swap. `src/zupt_mlock.c`
 *          traz três implementações selecionadas por compilação: POSIX
 *          (`mlock`), Windows (`VirtualLock`) e um caminho sem suporte, que é
 *          no-op e reporta falha.
 * @param[in] ptr Início do intervalo.
 * @param[in] len Tamanho do intervalo, em bytes.
 * @return 0 quando o bloqueio foi aceito pelo SO; -1 quando não suportado ou
 *         recusado (por exemplo limite de `RLIMIT_MEMLOCK`).
 * @note Sucesso depende do SO e do limite de memória bloqueável do processo:
 *       um retorno 0 não é garantia de que a região nunca saia da RAM.
 * @see zupt_munlock_keys, zupt_secure_wipe
 */
int  zupt_mlock_keys(void *ptr, size_t len);
/**
 * @brief  Desfaz o bloqueio de RAM feito por @ref zupt_mlock_keys.
 * @param[in] ptr Início do intervalo, como foi passado a @ref zupt_mlock_keys.
 * @param[in] len Tamanho do intervalo, em bytes.
 * @note Não limpa o conteúdo: chame @ref zupt_secure_wipe antes.
 */
void zupt_munlock_keys(void *ptr, size_t len);

/* ─── Adaptive compression: file type detection ─── */
/* Returns: -1=store (incompressible), 0=default, 5=medium, 9=max */
/**
 * @brief  Sugere um nível de compressão a partir do cabeçalho do arquivo.
 * @details Heurística de "compressão adaptativa": examina os primeiros bytes de
 *          um arquivo para decidir se vale a pena comprimir e com que esforço.
 *          A semântica do valor devolvido está indicada no comentário do
 *          cabeçalho:
 *          - `-1` = armazenar sem compressão (conteúdo já comprimido/incompressível);
 *          - `0`  = usar o nível padrão;
 *          - `5`  = nível médio;
 *          - `9`  = nível máximo.
 * @param[in] header       Primeiros bytes do arquivo.
 * @param[in] header_len   Quantidade de bytes disponíveis em `header`.
 * @return Um dos valores acima; `header_len` pequeno tende a devolver o padrão.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas
 *       não possui definição em `src/`.
 * @see ZUPT_CODEC_STORE, zupt_options_t::level
 */
int zupt_detect_filetype(const uint8_t *header, size_t header_len);

/* ─── XXH64 ─── */
uint64_t zupt_xxh64(const void *data, size_t len, uint64_t seed);

/* ─── LZ ─── */
/**
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
 */
size_t zupt_lz_compress(const uint8_t *src, size_t slen, uint8_t *dst, size_t dcap, int level);
/**
 * @brief Descompressão do formato produzido por `zupt_lz_compress`.
 * @param[in] src dados comprimidos.
 * @param[in] slen tamanho da entrada comprimida, em bytes.
 * @param[out] dst buffer de destino.
 * @param[in] dlen tamanho exato esperado da saída, em bytes.
 * @return Tamanho do resultado; a convenção de erro não é afirmável nesta revisão.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 */
size_t zupt_lz_decompress(const uint8_t *src, size_t slen, uint8_t *dst, size_t dlen);
/**
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
 */
size_t zupt_lz_bound(size_t slen);

/* ─── LZH (LZ77 + Huffman) ─── */
/**
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
 */
size_t zupt_lzh_compress(const uint8_t *src, size_t slen, uint8_t *dst, size_t dcap, int level);
/**
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
 */
size_t zupt_lzh_decompress(const uint8_t *src, size_t slen, uint8_t *dst, size_t dlen);
/**
 * @brief Calcula o limite superior de tamanho para o resultado de `zupt_lzh_compress`.
 *
 * A fórmula concreta não pode ser afirmada nesta revisão: a função não tem implementação em `src/`
 * nem é exercida por nenhum teste do repositório.
 * @param[in] slen tamanho, em bytes, do dado de entrada.
 * @return número de bytes necessários para comportar qualquer saída de `zupt_lzh_compress` para
 * essa entrada.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 */
size_t zupt_lzh_bound(size_t slen);

/* ─── Byte Prediction (order-1 context transform) ─── */
/**
 * @brief Constrói a tabela de predição de contexto de ordem 1 a partir de dados de treino.
 *
 * O cabeçalho descreve o grupo como "Byte Prediction (order-1 context transform)": o filtro subtrai
 * a previsão do byte corrente, realçando a redundância local antes da compressão.
 * @param[in] data dados usados para estimar o contexto.
 * @param[in] len tamanho dos dados de treino, em bytes.
 * @param[out] prediction tabela de 256 entradas, preenchida com a previsão para cada byte anterior.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 */
void  zupt_predict_build(const uint8_t *data, size_t len, uint8_t prediction[256]);
/**
 * @brief Aplica o filtro de predição (subtração da previsão) a um bloco.
 * @param[in] in dados originais.
 * @param[out] out recebe os dados residuais.
 * @param[in] len (parâmetro sem descrição manual — revisar)
 * @param[in] pred (parâmetro sem descrição manual — revisar)
 * @return `ZUPT_OK` em sucesso, ou código de erro.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 */
void  zupt_predict_encode(const uint8_t *in, uint8_t *out, size_t len, const uint8_t pred[256]);
/**
 * @brief Reverte o filtro de predição, reconstruindo os dados originais a partir dos resíduos.
 * @param[in] in dados residuais produzidos por `zupt_predict_encode`.
 * @param[out] out recebe os dados reconstruídos.
 * @param[in] len (parâmetro sem descrição manual — revisar)
 * @param[in] pred (parâmetro sem descrição manual — revisar)
 * @return `ZUPT_OK` em sucesso, ou código de erro.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 */
void  zupt_predict_decode(const uint8_t *in, uint8_t *out, size_t len, const uint8_t pred[256]);
/**
 * @brief Estima o ganho esperado de predição para um tipo de dado.
 *
 * Usado pela heurística de escolha de codec para decidir se vale aplicar o filtro de predição.
 * @param[in] data amostra dos dados a avaliar.
 * @param[in] len tamanho da amostra, em bytes.
 * @return Estimativa de ganho; a unidade não pode ser afirmada nesta revisão por falta de
 * implementação e de testes.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 */
float zupt_predict_benefit(const uint8_t *data, size_t len);

/* ─── Format I/O ─── */
/**
 * @brief Escreve um inteiro sem sinal em formato varint em um fluxo.
 *
 * A codificação exata dos bytes não pode ser afirmada nesta revisão (função sem implementação em
 * `src/`).
 * @param[out] f fluxo de saída.
 * @param[in] v valor a escrever.
 * @return Código da família `zupt_error_t`; `ZUPT_OK` em sucesso.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 */
int zupt_write_varint(FILE *f, uint64_t v);
/**
 * @brief Lê um inteiro sem sinal em formato varint de um `FILE*`.
 * @param[out] f fluxo de entrada.
 * @param[out] v (parâmetro sem descrição manual — revisar)
 * @return `ZUPT_OK` em sucesso, ou código de erro em fim de arquivo, varint malformado ou estouro.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 */
int zupt_read_varint(FILE *f, uint64_t *v);
/**
 * @brief Codifica um inteiro sem sinal em varint dentro de um buffer.
 * @param[out] b (parâmetro sem descrição manual — revisar)
 * @param[in] v valor a codificar.
 * @return `ZUPT_OK` em sucesso, ou código de erro se a codificação não couber em `dcap`.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 */
int zupt_encode_varint(uint8_t *b, uint64_t v);
/**
 * @brief Decodifica um varint a partir de um buffer.
 * @param[in] b (parâmetro sem descrição manual — revisar)
 * @param[in] blen (parâmetro sem descrição manual — revisar)
 * @param[out] v recebe o valor decodificado.
 * @return `ZUPT_OK` em sucesso, ou código de erro em varint truncado ou malformado.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 */
int zupt_decode_varint(const uint8_t *b, size_t blen, uint64_t *v);

/**
 * @brief Inicializa a lista de arquivos usada pelas APIs de arquivamento.
 * @param[out] fl lista a inicializar.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 */
void zupt_filelist_init(zupt_filelist_t *fl);
/**
 * @brief Libera toda a memória interna de uma lista de arquivos.
 *
 * Depois desta chamada o objeto só pode ser reutilizado com nova @ref zupt_filelist_init.
 * @param[out] fl lista criada por @ref zupt_filelist_init.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 */
void zupt_filelist_free(zupt_filelist_t *fl);
/**
 * @brief Acrescenta um arquivo à lista, separando caminho físico e nome no arquivo.
 * @param[out] fl lista ativa.
 * @param[in] disk_path caminho real do arquivo no sistema de arquivos.
 * @param[in] arc_path nome relativo que o arquivo terá dentro do contêiner.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 */
void zupt_filelist_add(zupt_filelist_t *fl, const char *disk_path, const char *arc_path);
/**
 * @brief Percorre um diretório e acrescenta recursivamente seus arquivos à lista.
 * @param[out] fl lista ativa.
 * @param[in] path diretório a percorrer.
 * @param[in] base prefixo removido dos caminhos para formar os nomes internos.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 */
void zupt_collect_files(zupt_filelist_t *fl, const char *path, const char *base);

/**
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
 */
zupt_error_t zupt_compress_files(const char *out, const char **arc, const char **disk, int n, zupt_options_t *opts);
/**
 * @brief Extrai todos os arquivos de um contêiner `.zupt` para um diretório.
 * @param[in] arc caminho do contêiner.
 * @param[in] dir diretório de destino.
 * @param[out] opts opções (incluem a chave para contêineres cifrados).
 * @return `ZUPT_OK` em sucesso, ou código de erro (autenticação, E/S, formato).
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 */
zupt_error_t zupt_extract_archive(const char *arc, const char *dir, zupt_options_t *opts);
/**
 * @brief Lista o conteúdo de um contêiner `.zupt` sem extrair os arquivos.
 * @param[in] arc caminho do contêiner.
 * @param[out] opts opções de leitura.
 * @return `ZUPT_OK` em sucesso, ou código de erro.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 */
zupt_error_t zupt_list_archive(const char *arc, zupt_options_t *opts);
/**
 * @brief Verifica a integridade de um contêiner `.zupt` sem materializar os arquivos.
 * @param[in] arc caminho do contêiner.
 * @param[out] opts opções de leitura.
 * @return `ZUPT_OK` quando o contêiner é íntegro, ou código de erro indicando a falha.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 */
zupt_error_t zupt_test_archive(const char *arc, zupt_options_t *opts);

/* ─── Hybrid PQ KEM (ML-KEM-768 + X25519) ─── */
/**
 * @brief Gera o par de chaves híbrido pós-quântico (ML-KEM-768 + X25519) em um arquivo.
 *
 * A geração usa @ref zupt_x25519_base e os primitivos de `include/zupt_mlkem.h`; o formato do
 * arquivo de chave é o descrito por `ZUPT_KEY_FORMAT_VERSION`.
 * @param[in] keyfile arquivo onde o par de chaves será gravado.
 * @return 0 em sucesso, ou código de erro.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 */
int zupt_hybrid_keygen(const char *keyfile);
/**
 * @brief Deriva o arquivo de chave pública a partir do arquivo de chave privada.
 * @param[in] privfile arquivo de chave privada.
 * @param[in] pubfile arquivo de chave pública a criar.
 * @return 0 em sucesso, ou código de erro.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 */
int zupt_hybrid_export_pubkey(const char *privfile, const char *pubfile);
/**
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
 */
int zupt_hybrid_encrypt_init(zupt_keyring_t *kr, const char *pubkeyfile,
                              uint8_t *enc_hdr, size_t *enc_hdr_len);
/**
 * @brief Estabelece a sessão híbrida para descriptografar, a partir de chave privada em arquivo.
 * @param[out] kr keyring que receberá as chaves de sessão.
 * @param[in] privkeyfile arquivo de chave privada.
 * @param[in] enc_hdr cabeçalho de sessão recebido.
 * @param[in] enc_hdr_len tamanho do cabeçalho recebido.
 * @return 0 em sucesso, ou código de erro.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 */
int zupt_hybrid_decrypt_init(zupt_keyring_t *kr, const char *privkeyfile,
                              const uint8_t *enc_hdr, size_t enc_hdr_len);
/* In-memory variants: take the key material directly from a buffer instead of
 * a file path, so callers never have to stage (private) keys on disk. */
/**
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
 */
int zupt_hybrid_encrypt_init_mem(zupt_keyring_t *kr,
                                  const uint8_t *pubkey, size_t pubkey_len,
                                  uint8_t *enc_hdr, size_t *enc_hdr_len);
/**
 * @brief Variante em memória de @ref zupt_hybrid_decrypt_init, com chave privada em buffer.
 * @param[out] kr keyring que receberá as chaves de sessão.
 * @param[in] privkey chave privada em buffer.
 * @param[in] privkey_len tamanho da chave privada, em bytes.
 * @param[in] enc_hdr cabeçalho de sessão recebido.
 * @param[in] enc_hdr_len tamanho do cabeçalho recebido.
 * @return 0 em sucesso, ou código de erro.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 */
int zupt_hybrid_decrypt_init_mem(zupt_keyring_t *kr,
                                  const uint8_t *privkey, size_t privkey_len,
                                  const uint8_t *enc_hdr, size_t enc_hdr_len);

/**
 * @brief Devolve a descrição legível de um código de erro.
 * @param[in] e código de erro da família `zupt_error_t`.
 * @return Cadeia de caracteres estática; nunca deve ser liberada pelo chamador.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 */
const char *zupt_strerror(zupt_error_t e);
/**
 * @brief Devolve o nome legível de um identificador de codec.
 * @param[in] id identificador do codec (ver macros `ZUPT_CODEC_*`).
 * @return Cadeia de caracteres estática com o nome do codec.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 */
const char *zupt_codec_name(uint16_t id);
/**
 * @brief Preenche uma estrutura de opções com os valores padrão.
 *
 * Necessário antes de usar `zupt_options_t`, cujas macros de definição de valores dependem de um
 * estado inicial coerente.
 * @param[out] o estrutura a inicializar.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 */
void zupt_default_options(zupt_options_t *o);
/**
 * @brief Formata uma contagem de bytes em texto legível para exibição.
 * @param[in] bytes quantidade de bytes a formatar.
 * @param[out] buf buffer de destino da cadeia formatada.
 * @param[in] cap capacidade do buffer, em bytes.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 */
void zupt_format_size(uint64_t bytes, char *buf, size_t cap);

/* Resolve ZUPT_CODEC_AUTO to a concrete codec based on hardware.
 * On x86_64 with AVX2: VaptVupt (fast ANS+SIMD decode).
 * On all other arches:  Zupt-LZHP (no SIMD dependency).
 * Decompression of ALL codecs works on ALL architectures. */
/**
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
 */
uint16_t zupt_resolve_auto_codec(void);

/* ─── Full-Disk Backup/Restore ─── */
/**
 * @def ZUPT_FLAG_DISK_IMAGE
 * @brief Flag de arquivo indicando que o conteúdo é uma imagem de disco.
 * @details O campo `global_flags` de @ref zupt_archive_header_t é um
 *          bitfield; este bit informa ao leitor que o conteúdo deve ser
 *          tratado como imagem bruta, por exemplo para restauração direta.
 * @note    Não há, em `src/`, código que consulte este bit.
 */
#define ZUPT_FLAG_DISK_IMAGE   (1u << 6)  /* Archive contains a raw disk/partition image */

/* Compress a raw block device or file as a disk image.
 * Reads source in block_size chunks, detects zero/sparse regions,
 * compresses non-zero blocks. Supports encryption + PQ. */
/**
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
 */
zupt_error_t zupt_disk_backup(const char *output_path, const char *source_path,
                               zupt_options_t *opts);

/* Restore a disk image archive to a block device or file.
 * Writes blocks sequentially, restoring sparse regions as zeros. */
/**
 * @brief Restaura uma imagem de disco gravada por @ref zupt_disk_backup.
 *
 * Grava os blocos em sequência, reconstituindo as regiões radiciais como zeros.
 * @param[in] archive_path contêiner a restaurar.
 * @param[in] target_path dispositivo de blocos ou arquivo de destino.
 * @param[out] opts opções de restauração.
 * @return `ZUPT_OK` em sucesso, ou código de erro.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 */
zupt_error_t zupt_disk_restore(const char *archive_path, const char *target_path,
                                zupt_options_t *opts);

/* ─── Internal Block I/O (used by format + disk modules) ─── */
/**
 * @brief Lê o cabeçalho e a carga de um bloco do contêiner.
 *
 * Símbolo de uso interno dos módulos de formato; não faz parte da API pública.
 * @param[out] f fluxo posicionado no início do bloco.
 * @param[out] b recebe o bloco lido.
 * @return `ZUPT_OK` em sucesso, ou código de erro de E/S/formato.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 */
zupt_error_t read_block(FILE *f, zupt_block_t *b);
/**
 * @brief Lê e valida o cabeçalho de um contêiner cifrado.
 * @param[out] f fluxo posicionado no início do arquivo.
 * @param[out] hdr recebe o cabeçalho lido.
 * @param[out] opts recebe as opções derivadas do cabeçalho.
 * @return `ZUPT_OK` em sucesso, ou `ZUPT_ERR_MAGIC`/`ZUPT_ERR_FORMAT` em cabeçalho inválido.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 */
zupt_error_t read_enc_header(FILE *f, zupt_archive_header_t *hdr, zupt_options_t *opts);
/**
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
 */
zupt_error_t decompress_block(const zupt_block_t *b, const zupt_keyring_t *kr,
                               uint64_t block_seq, uint8_t **out, size_t *olen);
/**
 * @brief Escreve o cabeçalho de um contêiner cifrado.
 * @param[out] out fluxo de saída.
 * @param[out] hdr cabeçalho a gravar.
 * @param[out] opts opções usadas na geração do cabeçalho.
 * @return `ZUPT_OK` em sucesso, ou código de erro de E/S.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 */
zupt_error_t write_enc_header(FILE *out, zupt_archive_header_t *hdr,
                               zupt_options_t *opts);
/**
 * @brief Escreve um byte em little-endian em um fluxo.
 * @param[out] f fluxo de saída.
 * @param[in] v valor a escrever.
 * @return 0 em sucesso, ou código de erro de E/S.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 */
int zupt_w8(FILE *f, uint8_t v);
/**
 * @brief Escreve um inteiro de 16 bits little-endian em um fluxo.
 * @param[out] f fluxo de saída.
 * @param[in] v valor a escrever.
 * @return 0 em sucesso, ou código de erro de E/S.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 */
int zupt_w16le(FILE *f, uint16_t v);
/**
 * @brief Escreve um inteiro de 64 bits little-endian em um fluxo.
 * @param[out] f fluxo de saída.
 * @param[in] v valor a escrever.
 * @return 0 em sucesso, ou código de erro de E/S.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 */
int zupt_w64le(FILE *f, uint64_t v);

/* ─── Block-Level Deduplication ─── */
/**
 * @def ZUPT_DEDUP_MAX_ENTRIES
 * @brief Limite de entradas da tabela de desduplicação em memória (2 Mi).
 * @details Dimensiona o índice interno de @ref zupt_dedup_ctx_t.
 * @see ZUPT_BLOCK_DEDUP_REF
 */
#define ZUPT_DEDUP_MAX_ENTRIES  (2 * 1024 * 1024)  /* 2M entries, ~48MB RAM */

/**
 * @typedef  struct zupt_dedup_ctx zupt_dedup_ctx_t
 * @brief    Contexto opaco do índice de desduplicação em memória.
 * @details    Os membros não são expostos: o layout é interno ao módulo de
 *            desduplicação. O tamanho máximo da tabela é
 *            @ref ZUPT_DEDUP_MAX_ENTRIES.
 */
typedef struct zupt_dedup_ctx zupt_dedup_ctx_t;

/**
 * @brief Cria o contexto de deduplicação em nível de bloco.
 *
 * O contexto guarda a tabela de impressões digitais de blocos já vistos; o limite de entradas é
 * `ZUPT_DEDUP_MAX_ENTRIES`, cujo comentário no cabeçalho estima cerca de 48 MB de RAM.
 *
 * Serve tanto a arquivagem comum quanto à imagem de disco, onde regiões repetidas são frequentes.
 * @return Ponteira para o contexto criado, ou `NULL` se a alocação falhar.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 */
zupt_dedup_ctx_t *zupt_dedup_init(void);
/**
 * @brief Libera o contexto de deduplicação.
 * @param[out] ctx contexto criado por @ref zupt_dedup_init.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 */
void zupt_dedup_free(zupt_dedup_ctx_t *ctx);
/**
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
 */
int  zupt_dedup_lookup(zupt_dedup_ctx_t *ctx, uint64_t fingerprint,
                       uint64_t *ref_offset, uint32_t *ref_size);
/**
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
 */
int  zupt_dedup_insert(zupt_dedup_ctx_t *ctx, uint64_t fingerprint,
                       uint64_t block_offset, uint32_t block_size);
/**
 * @brief Acumula a estatística de bytes economizados por uma correspondência.
 * @param[out] ctx contexto ativo.
 * @param[in] saved_bytes quantidade de bytes economizados neste acerto.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 */
void zupt_dedup_record_hit(zupt_dedup_ctx_t *ctx, uint64_t saved_bytes);
/**
 * @brief Conta um bloco examinado nas estatísticas de deduplicação.
 * @param[out] ctx contexto ativo.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 */
void zupt_dedup_record_block(zupt_dedup_ctx_t *ctx);
/**
 * @brief Devolve os contadores acumulados de deduplicação.
 * @param[in] ctx contexto ativo.
 * @param[out] blocks_seen recebe o total de blocos examinados.
 * @param[out] blocks_deduped recebe o total de blocos substituídos por referência.
 * @param[out] bytes_saved recebe o total de bytes economizados.
 * @note Nesta revisão do repositório, o símbolo é declarado neste cabeçalho mas não possui
 * definição em `src/`.
 */
void zupt_dedup_stats(const zupt_dedup_ctx_t *ctx,
                      uint64_t *blocks_seen, uint64_t *blocks_deduped,
                      uint64_t *bytes_saved);
/**
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
 */
int  zupt_dedup_write_ref(FILE *out, uint64_t ref_offset,
                          uint32_t orig_size, uint64_t orig_checksum);

#endif /* ZUPT_H */
