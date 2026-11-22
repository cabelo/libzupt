/**
 * @page page-memoria Propriedade de memória e limpeza
 *
 * @brief Quem aloca, quem libera, o que é zerado e o que é travado em RAM.
 *
 * @details
 *
 * # Propriedade dos buffers
 *
 * | Origem | Liberação |
 * | --- | --- |
 * | Buffer fornecido pelo chamador com capacidade (`dst`, `out`, `h`, `buf`) | O chamador mantém a propriedade; a biblioteca apenas escreve |
 * | Ponteiro devolvido por `zupt_encrypt_buffer()`, `zupt_decrypt_buffer()`, `zupt_read_file()` | O chamador libera com `free()` |
 * | `char **paths` dentro de `zupt_filelist_t` | Ciclo de vida não confirmável nesta árvore: `zupt_filelist_free()`, que deveria liberá-lo, é declarada em `include/zupt.h` mas não tem definição em `src/` |
 * | Contextos (`zupt_sha256_ctx`, `zupt_aes256_ctx`, `zupt_keccak_ctx`, `zupt_keyring_t`) | Variáveis do chamador, em pilha ou heap; nenhuma liberação interna |
 *
 * Não há contrato de realocação: quando a capacidade informada é menor que o
 * necessário, as funções que recebem buffer e capacidade devolvem `0`
 * (@ref zupt_lz_compress, @ref zupt_lzh_compress) em vez de crescer o buffer.
 *
 * # Limpeza de material sensível
 *
 * - `zupt_secure_wipe()`, `static inline` em `include/zupt.h:748`, tem quatro
 *   ramos: `SecureZeroMemory()` em Windows, `explicit_bzero()` quando a glibc é
 *   2.25 ou mais nova e também em FreeBSD/OpenBSD, e uma volta `for` por uma
 *   cópia `volatile uint8_t *` nos demais casos. O último ramo é a barreira que
 *   impede o otimizador de eliminar a limpeza. Os ramos não-Linux não são
 *   compilados nesta build.
 * - `zupt_keyring_check()` confere os campos `canary_head` e `canary_tail`
 *   contra `ZUPT_CANARY`. Ela detecta sobrescrita da estrutura do chaveiro, não
 *   de uma chave isolada, e o comportamento na detecção é interromper o processo.
 * - `src/zupt_mlock.c` define `zupt_mlock_keys()` e `zupt_munlock_keys()` em
 *   três ramos. No ramo POSIX/BSD/Apple, `mlock()` recusado imprime um aviso em
 *   `stderr` e devolve `-1`. No ramo Windows é usado `VirtualLock()`. No ramo de
 *   reserva (nenhum dos dois anteriores) `zupt_mlock_keys()` ignora os argumentos
 *   e devolve `-1` sempre, e `zupt_munlock_keys()` apenas executa a limpeza.
 *
 * @warning `mlock()` depende do limite `RLIMIT_MEMLOCK`. Sem privilégio, ou em
 *          contêineres com o limite baixo, o bloqueio falha: o retorno `-1`
 *          indica que as páginas continuaram pagináveis e um aviso vai a
 *          `stderr`. Nenhuma chamada de `zupt_mlock_keys()` em `src/` testa esse
 *          retorno.
 *
 * # Pontos que merecem atenção
 *
 * - `zupt_derive_keys()` deriva 64 bytes em uma variável local (`material`),
 *   distribui `enc_key` e `mac_key` e limpa `material` com `zupt_secure_wipe()`
 *   antes de sair. A senha, porém, é lida com `strlen()`: uma senha contendo
 *   byte nulo é truncada silenciosamente e a chave resultante difere da
 *   esperada.
 * - A mesma função chama `zupt_mlock_keys()` sobre `enc_key` e `mac_key`
 *   separadamente e descarta os retornos. Quando o chaveiro é uma variável em
 *   pilha, as duas regiões não são alinhadas a página e o `mlock()` tende a
 *   falhar, de modo que a chave pode acabar em swap mesmo no caminho de sucesso.
 * - `zupt_decrypt_buffer()` confere o HMAC e o nonce antes de alocar o texto
 *   plano, mas **sempre decifra**, inclusive quando a autenticação falhou: o
 *   objetivo declarado é evitar um oráculo de tempo que revelasse MACs válidos.
 *   O texto plano decifrado é então zerado e liberado, e `NULL` é devolvido.
 *   Enquanto dura, porém, existe um buffer com bytes decifrados de dados
 *   não autenticados.
 *
 * @see \ref page-seguranca e \ref page-limitacoes.
 */
