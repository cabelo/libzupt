/**
 * @page page-erros Códigos e tratamento de erros
 *
 * @brief ::zupt_error_t, funções que não o usam e o que cada código significa.
 *
 * @details
 *
 * # O enumerado
 *
 * @ref zupt_error_t define um valor zero e dez códigos negativos:
 *
 * | Constante | Valor | Sentido |
 * | --- | --- | --- |
 * | `ZUPT_OK` | 0 | Sucesso |
 * | `ZUPT_ERR_IO` | -1 | Falha de leitura ou escrita em disco |
 * | `ZUPT_ERR_CORRUPT` | -2 | Estrutura interna inconsistente |
 * | `ZUPT_ERR_BAD_MAGIC` | -3 | Magic inválido |
 * | `ZUPT_ERR_BAD_VERSION` | -4 | Versão de formato não suportada |
 * | `ZUPT_ERR_BAD_CHECKSUM` | -5 | Checksum divergente |
 * | `ZUPT_ERR_NOMEM` | -6 | Alocação de memória falhou |
 * | `ZUPT_ERR_OVERFLOW` | -7 | Saída maior que a capacidade informada |
 * | `ZUPT_ERR_INVALID` | -8 | Argumento inválido, por exemplo `NULL` |
 * | `ZUPT_ERR_NOT_FOUND` | -9 | Entrada ou arquivo não existe |
 * | `ZUPT_ERR_UNSUPPORTED` | -10 | Recurso não implementado |
 * | `ZUPT_ERR_AUTH_FAIL` | -11 | Autenticação falhou, MAC divergente |
 *
 * A função `zupt_strerror()` devolve uma descrição textual do código. Nesta
 * revisão do repositório ela é declarada em `include/zupt.h` mas não tem
 * definição em `src/`.
 *
 * # Onde o código de erro não é usado
 *
 * Boa parte da API devolve outro tipo, e esses casos não passam por
 * `zupt_error_t`:
 *
 * - Funções de cifra em baixo nível (`zupt_sha256_update()`,
 *   `zupt_aes256_ctr()`, `zupt_hmac_sha256()`) devolvem `void`: validação de
 *   tamanho é responsabilidade do chamador.
 * - `zupt_encrypt_buffer()` e `zupt_decrypt_buffer()` devolvem `uint8_t *` e
 *   `NULL` em falha. `NULL` não distingue MAC inválido, comprimento inconsistente
 *   e falta de memória.
 * - `zupt_derive_keys()` devolve `void` e não reporta erro.
 * - `zupt_random_bytes()` devolve `void`. Se a fonte de aleatoriedade falha, o
 *   processo é encerrado com `exit(1)` em `src/zupt_crypto.c`, o que faz dela
 *   insegura para uso em bibliotecas dentro de um processo que precisa tratar a
 *   falha.
 * - As funções de compressão (`zupt_lz_compress()`, `zupt_lzh_decompress()`)
 *   devolvem `size_t` e usam `0` como sinal de falha.
 *
 * # Convenções do chamador
 *
 * - Trate qualquer valor diferente de `ZUPT_OK` como falha, inclusive
 *   `ZUPT_OK` seguido de saída vazia.
 * - Depois de `ZUPT_ERR_AUTH_FAIL`, descarte o buffer de entrada: o contêiner é
 *   ou uma senha errada ou um arquivo adulterado.
 * - `ZUPT_ERR_BAD_VERSION` costuma indicar arquivo escrito por outra versão da
 *   biblioteca; as divergências de versão registradas em \ref page-limitacoes
 *   tornam esse diagnóstico ambíguo.
 */
