@page page-limitacoes Limitações conhecidas e comportamentos que surpreendem

# Limitações conhecidas

Limitações verificadas lendo o código e a configuração de build desta árvore.
Nenhuma delas é corrigida aqui: são registradas como estão. Onde há um número de
linha, ele foi conferido nesta árvore.

## A versão que você lê depende de onde você olha

O valor da versão não é consistente entre os canais:

| Canal | Onde é lido | Valor |
|---|---|---|
| `LIBZUPT_VERSION_STRING` | `include/libzupt_version.h:29` | `"1.0.15"` |
| `ZUPT_VERSION_STRING` | `include/zupt.h:120` | `"2.1.5"` |
| Formato da chave | `include/zupt.h:126, 134` | 1 e 4 |
| Formato da chave (C++) | `include/zupt_cxx.h:52` | 2 |
| Formato do envelope (C++) | `include/zupt_cxx.h:64` | 3 |
| `README.md` | `README.md:10, 19` | `"2.0.0"` |

Os dois primeiros canais têm origens distintas. `CMakeLists.txt:2-4` lê
`include/libzupt_version.h`, extrai `major.minor.patch` da linha que define
`LIBZUPT_VERSION_STRING` por expressão regular e entrega o resultado a
`project(libzupt VERSION ...)` (`CMakeLists.txt:5`); é desse valor que saem
`PROJECT_VERSION`, o `VERSION`/`SOVERSION` da biblioteca compartilhada
(`CMakeLists.txt:80-81`) e a versão do `libzupt.pc`. Não existe cabeçalho de
versão gerado pelo build — a árvore não produz nenhum `build/libzupt_version.h`,
e a regra de instalação copia o próprio `include/libzupt_version.h`
(`CMakeLists.txt:141`). A extração por expressão regular impõe o formato: a
macro precisa começar a linha e conter exatamente três números separados por
ponto, senão `PROJECT_VERSION` não é derivado. `zupt.h:120` declara a sua
própria string, independente de tudo isso.

Não há função C que devolva a versão. O único acesso programático é
`zupt::getVersion()` (`src/zupt_crypto.cpp:420`), que devolve
`LIBZUPT_VERSION_STRING`. Uma aplicação que precise comparar a versão vinculada
com a compilada não tem esse canal no C puro, e os quatro números de formato
(1, 4, 2, 3) não se referem à mesma entidade.

## Só três cabeçalhos são instalados

A única regra `install(FILES ...)` que copia cabeçalhos (`CMakeLists.txt:138-143`)
instala `include/zupt.hpp`, `include/zupt_cxx.h` e `include/libzupt_version.h`.
As metas exportadas apontam o consumidor para esse diretório
(`$<INSTALL_INTERFACE:include>` em `CMakeLists.txt:62` e `:100`), e o `libzupt.pc`
faz o mesmo com `Cflags: -I${includedir}`. Portanto:

- `include/zupt.h` — a interface C completa — **não é instalada**;
- `include/zupt_mlkem.h`, `include/zupt_x25519.h`, `include/zupt_keccak.h` e
  `include/zupt_cpuid.h` — **não são instaladas**;
- os objetos da biblioteca contêm todos os símbolos dessas interfaces, mas o
  pré-processador do consumidor não encontra as declarações.

O que sobra é uma instalação coerente apenas para a API C++: `zupt.hpp` inclui
`zupt_cxx.h` (`include/zupt.hpp:53`) e `zupt_cxx.h` depende só de `<stdint.h>` e
`<stddef.h>` (`include/zupt_cxx.h:35-36`), então nenhum dos arquivos instalados
referencia `zupt.h`. Para usar a API C é preciso compilar a partir da árvore de
origem ou copiar `zupt.h` à mão.

## O dispatch de AES-NI/AVX lê um símbolo que ninguém define

O dispatch em `src/zupt_crypto.c:433` escolhe entre o caminho assembly e o
portátil lendo `zupt_cpu.has_aesni && zupt_cpu.has_avx`, e essa linha só existe
sob `-DZUPT_USE_JASMIN`. `zupt_cpu` é declarado `extern` em
`include/zupt_cpuid.h:70` e `zupt_detect_cpu()` em `include/zupt_cpuid.h:56`;
nenhum `src/*.c` define qualquer dos dois.

No build padrão (`ZUPT_USE_JASMIN` desligado) o código que os referencia nem é
compilado, e tudo linka. Com a macro ligada, a biblioteca compartilhada ainda é
construída — o vinculador aceita símbolos indefinidos em objeto compartilhado —
mas linkar um executável que chegue a esse ramo falha por símbolo não resolvido.
É um caminho que depende de o chamador fornecer a definição por fora, sem que a
biblioteca exponha como. `zupt_detect_cpu()`, aliás, não é chamada em lugar
nenhum desta árvore: mesmo quem a definisse nunca teria seu resultado
consumido.

## `zupt_random_bytes()` encerra o processo em vez de reportar erro

`src/zupt_crypto.c:126` define `zupt_random_bytes()`. Quando a obtenção de
entropia falha, a função escreve em `stderr` e chama `exit(1)`
(`src/zupt_crypto.c:137` e `:153`), porque salt e nonce não podem ser
previsíveis. O efeito colateral é que uma biblioteca devolve um erro terminal: o
chamador não tem como tratar a situação, recuperar-se dela ou escolher outra
fonte de entropia. Onde isso importa, a alternativa é gerar os aleatórios por
conta própria e chamar as variantes que recebem salt e nonce como argumentos.

## `zupt_decrypt_buffer()` tem três causas de falha e um só sinal

`src/zupt_crypto.c:738` retorna `NULL` em exatamente três pontos:

1. `pkglen < ZUPT_NONCE_SIZE + ZUPT_HMAC_SIZE` (linha 741);
2. `malloc` do texto em claro falhou (linha 777);
3. autenticação falhou — MAC divergente ou nonce não vinculado ao bloco e ao
   cabeçalho (linhas 782 a 786).

As três causas produzem o mesmo resultado observável, e `*olen` é preenchida
antes da verificação do MAC, de modo que um `NULL` de autenticação chega com um
comprimento plausível escrito no apontador. Não há código de erro nem canal de
diagnóstico. `pkg` e `kr` também não são verificados contra nulo: o primeiro
acesso é a própria `pkg`, na chamada de HMAC (`src/zupt_crypto.c:748`), e o
primeiro acesso a `kr` é `kr->mac_key`, na mesma linha — `pkg == NULL` com
`pkglen >= 48` é violação de acesso, não erro tratado. Distinguir "formato
inválido" de "chave errada" de "sem memória" exige verificar o digest e o
comprimento antes de chamar.

## Keccak: dois caminhos sem guarda, só alcançáveis por engano

Os helpers internos têm dois estados que eles mesmos não rejeitam. Nenhum dos
dois é alcançável pelo uso correto das APIs públicas — todas as chamadas de
`keccak_init()` passam taxa positiva e fixa —, mas ambos ficam documentados
porque a reuso dos helpers os expõe.

- `keccak_absorb()` (`src/zupt_keccak.c`) calcula o espaço livre como
  `rate - pt`. Com `rate == 0`, o espaço é 0, o bloco copiado é 0 e cada
  iteração do laço só aplica uma permutação sem avançar o índice: o laço não
  termina.
- `keccak_finalize()` fecha o padding com
  `memset(ctx->buf + ctx->pt + 1, 0, ctx->rate - ctx->pt - 1)`. Os operandos
  são inteiros sem sinal, então com `pt == rate` o comprimento calculado
  envolve para um valor enorme e o `memset` escreve muito além de `buf`.

Os dois estão registrados como `@warning` nas próprias funções, na forma como
são hoje.

## A API C++: cabeçalho de envelope opaco e dois métodos sem corpo

A interface C++ (`include/zupt.hpp`, implementada em `src/zupt_crypto.cpp`) é
compatível com a C, mas tem três particularidades.

**O cabeçalho do envelope é um blob opaco.** As constantes que definem o
envelope v2 são privadas de `src/zupt_cxx.c`: `ZUPT_ENCRYPT_BLOCK_SIZE`
(4 MiB), `ENVELOPE_PREFIX` (12 — `"ZUP2"` mais o `u64le` do comprimento do texto
em claro) e `ENVELOPE_TAG` (32), em `src/zupt_cxx.c:242-247`; os 52 bytes de
acréscimo por registro de bloco aparecem como literal na fórmula de tamanho
(`src/zupt_cxx.c:362`). Nada disso está em `include/zupt.h`, então do lado C o
chamador recebe o envelope como `uint8_t*` com um tamanho e não tem como
interpretar os campos sem copiar as constantes de outro TU. Os 1137 bytes do
cabeçalho híbrido têm o mesmo problema do outro lado:
`Encryptor::getEncryptionHeaderSize()` (`include/zupt.hpp:546`) devolve a
constante `HYBRID_ENC_HEADER_SIZE`, mas nenhum accessor expõe um campo do
conteúdo.

**`Encryptor::initEncryptionHeader()` (`include/zupt.hpp:564`) e
`Decryptor::deriveKeys(const std::vector<uint8_t>&)` (`include/zupt.hpp:699`)
são declarados e não têm definição.** Não aparecem em `src/zupt_crypto.cpp` nem
em `build/libzupt_static.a`. Também não são chamados por nada nesta árvore, o
que explica por que a biblioteca linka: o vínculo falha apenas se um chamador
externo passar por eles. O mesmo vale para o membro
`Decryptor::encryptionHeader_` (`include/zupt.hpp:703`): nenhuma leitura ou
escrita sua existe em `src/` — todos os usos de `encryptionHeader_` que existem
são do `Encryptor`.

**`zupt::secureWipe` é declarado duas vezes** no mesmo cabeçalho, em
`include/zupt.hpp:229` e `include/zupt.hpp:742`, com assinatura idêntica. É
redundância, não conflito.

## Limitações das vinculações (bindings)

Os bindings em `examples_*` são exemplos que viram superfície pública: cada um
tem detalhes que um consumidor vai encontrar.

**Java (`examples_java/`).** `Encryptor.java` é a única classe que usa método
nativo sem `System.loadLibrary("Jzupt")` — `KeyGenerator.java:14`,
`Decryptor.java:10`, `NativeLib.java:9` e `ExampleBasic.java:10` têm o bloco
estático de carregamento. Se a aplicação usar só `Encryptor`, a biblioteca nunca
é carregada: `JNI_OnLoad` não roda, nenhum método é registrado e a chamada vira
`UnsatisfiedLinkError`. Além disso,
`Java_com_libzupt_Encryptor_nativeEncryptMemorySecure`
(`examples_java/zupt_jni.cpp:894`) está implementada mas não está na tabela
`encryptorMethods` (`zupt_jni.cpp:413`) nem é declarada como `native` em
`Encryptor.java` — `encryptMemorySecure` delega para `nativeEncryptMemory`
(`Encryptor.java:34`). Pelo mesmo caminho,
`Java_com_libzupt_Decryptor_decryptMemorySecure` (`zupt_jni.cpp:1062`) é código
morto: o método Java de mesmo nome (`Decryptor.java:39`) chama
`decryptMemoryNative` e só envolve o resultado num `SecureBuffer`. As contagens
de elementos passadas a `RegisterNatives` são literais repetidos à mão
(`zupt_jni.cpp:523, 529, 535, 541`), não `NELEMS`. Por fim, o arquivo não
implementa `JNI_OnUnload`, de modo que as referências globais criadas em
`JNI_OnLoad` não são liberadas quando a classe é descarregada.

**Python (`examples_python/zupt_pybind.cpp`).** `zupt::ZuptError` é registrada
com `py::register_exception` (`zupt_pybind.cpp:140`), que cria uma exceção
derivada de `RuntimeError` sem métodos: o código de erro de `ZuptError::code()`
se perde ao atravessar a fronteira, sobrando apenas a mensagem. `secure_wipe(ptr,
size)` (`zupt_pybind.cpp:742`) é encaminhamento direto para
`zupt::secureWipe(void*, size_t)` e recebe um endereço inteiro vindo do
interpretador: `secure_wipe(0, 16)` é uma escrita nula, sem verificação alguma.

**Node.js (`examples_nodejs/src/zupt_napi.cpp`).** Os argumentos numéricos são
convertidos com `Uint32Value()` (`zupt_napi.cpp:291` e `zupt_napi.cpp:853`), o
que faz `randomBytes(-1)` virar `4294967295` e a alocação tentar quatro gigabytes
em vez de reportar erro. As classes `Encryptor` e `Decryptor` não chamam
`IsBuffer()` em nenhum ponto do arquivo: um `napi_value` que não é `Buffer` chega
à conversão de ponteiro sem verificação.

## 52 símbolos declarados sem definição

Conferindo o que `include/` declara contra o que `build/libzupt_static.a`
efetivamente contém (`nm --defined-only`), 52 nomes aparecem nos cabeçalhos e em
nenhum objeto da biblioteca. Eles se dividem em dois grupos bem distintos.

**Jasmin e CPU (6 símbolos)** — `zupt_aes256_blk`, `zupt_aes256_ctr4`,
`zupt_ct_select_32`, `zupt_fe_cswap`, `zupt_mac_verify_ct` (declarados em
`include/zupt_jasmin.h`) e `zupt_detect_cpu` (`include/zupt_cpuid.h`). Não há
nenhum arquivo de assembly nesta árvore. Os cinco primeiros são chamados
somente dentro de blocos condicionais de compilação `ZUPT_USE_JASMIN`
(`src/zupt_crypto.c:427-475` e `:753`, `src/zupt_mlkem.c:1088` e
`src/zupt_x25519.c:252`); `zupt_detect_cpu` não tem nenhum ponto de chamada
fora da própria declaração. É o mesmo caso do dispatch de AES descrito
acima: a macro liga o consumo e não existe quem forneça a definição.

**Formato, compactação e desduplicação (46 símbolos)** — todo o conjunto de
arquivos, declarado em `include/zupt.h`:

- contêiner: `zupt_compress_files`, `zupt_compress_solid`,
  `zupt_extract_archive`, `zupt_list_archive`, `zupt_test_archive`;
- disco: `zupt_disk_backup`, `zupt_disk_restore`;
- codecs: `zupt_lz_compress`, `zupt_lz_decompress`, `zupt_lz_bound`,
  `zupt_lzh_compress`, `zupt_lzh_decompress`, `zupt_lzh_bound`,
  `zupt_predict_build`, `zupt_predict_encode`, `zupt_predict_decode`,
  `zupt_predict_benefit`, `zupt_resolve_auto_codec`, `zupt_codec_name`,
  `zupt_detect_filetype`;
- serialização interna: `zupt_w8`, `zupt_w16le`, `zupt_w64le`,
  `zupt_write_varint`, `zupt_read_varint`, `zupt_encode_varint`,
  `zupt_decode_varint`, `read_block`, `read_enc_header`,
  `write_enc_header`, `decompress_block`;
- desduplicação: `zupt_dedup_init`, `zupt_dedup_free`, `zupt_dedup_lookup`,
  `zupt_dedup_insert`, `zupt_dedup_record_hit`, `zupt_dedup_record_block`,
  `zupt_dedup_stats`, `zupt_dedup_write_ref`;
- utilidade e descoberta: `zupt_filelist_init`, `zupt_filelist_free`,
  `zupt_filelist_add`, `zupt_collect_files`, `zupt_default_options`,
  `zupt_format_size`, `zupt_strerror`.

O efeito prático: os tipos (`zupt_archive_header_t`, `zupt_index_entry_t`,
`zupt_block_t`, `zupt_dedup_ctx_t`), os identificadores de codec e os flags do
cabeçalho existem e descrevem um formato — mas nada nesta árvore produz ou
consome esse formato. Nenhuma chamada a esses 46 nomes aparece em `src/`, e eles
tampouco aparecem nos bindings nem em `tests/`.

O tipo de erro dessa metade da interface, `zupt_error_t` (`include/zupt.h:416`),
obedece a mesma regra: fora o próprio `include/zupt.h`, onde aparece em 19
linhas, ele não é citado em nenhum `src/`, `tests/` ou `examples_*`. As
implementações que de fato existem reportam falha por `NULL`, exceção C++
(`zupt::ZuptError`) ou `exit(1)`; o código de erro enumerado fica reservado para
funções que não existem.

## Os bits de flag do contêiner não são lidos por nada

Os oito `ZUPT_FLAG_*` definidos em `include/zupt.h` (linhas 210, 221, 229, 236,
245, 250, 257 e 1514) não aparecem em nenhum trecho executável de `src/`: se os
comentários são desconsiderados na busca, o resultado é vazio. Isso inclui
`ZUPT_FLAG_DISK_IMAGE` (bit 6), que `@ref zupt_disk_backup` recebe em `opts`
como se controlasse um comportamento, e `ZUPT_FLAG_CKSUM_XXH64`, que expande para
`(0u << 5)` — ligá-la não liga bit nenhum.

Em conjunto com a seção anterior, o retrato é coerente: os bits descrevem um
formato de arquivo cuja leitura e escrita não estão implementadas nesta árvore.

## Cobertura de testes

O `ctest` desta árvore roda 14 testes e os 14 passam. O que eles cobrem, porém,
é o núcleo criptográfico: `keygen`, `encrypt`, `decrypt`, `roundtrip`,
`file_ops`, `authentication`, `secure_buffer`, `key_storage` (somente em UNIX),
`fuzz_smoke`, mais quatro verificações em Python (`acvp`, `primitives`,
`legacy`, `migration_cli`) e um teste do AES portátil.

Dois pontos de atenção:

- `tests/fuzz_decrypt.cpp` não aparece em `tests/CMakeLists.txt`. O único alvo
  que o compila é `zupt_fuzz_decrypt` (`CMakeLists.txt:204-212`), protegido por
  `LIBZUPT_BUILD_FUZZERS`, que é `OFF` por padrão e exige Clang. Esse alvo não é
  registrado como caso de CTest, então `ctest` roda apenas `fuzz_smoke`.
- Nenhum teste alcança a API de arquivos e discos, o que era esperado: as
  funções não existem. Os testes de `file_ops` exercem só
  `Encryptor::encryptFile`/`Decryptor::decryptFile` da camada C++;
  `zupt_read_file` e `zupt_write_file` não são chamados por nenhum teste, e o
  contêiner `.zupt` não é lido nem escrito em lugar algum.
