/**
 * @page page-concorrencia Concorrência e reentrância
 *
 * @brief O que pode ser chamado de várias threads e o que não pode.
 *
 * @details
 *
 * # Estado global
 *
 * A análise de `src/*.c` e `src/*.cpp` não encontrou variável global ou estática
 * de arquivo mutável. As únicas entidades estáticas são tabelas constantes
 * (S-boxes do AES, tabelas do XXH64, constantes de curva) e funções estáticas.
 * Não há `pthread`, mutex, atômico ou `strtok_r` em nenhum dos fontes.
 *
 * # Consequências
 *
 * - As primitivas criptográficas (`zupt_sha256*`, `zupt_aes256*`,
 *   `zupt_hmac_sha256`, `zupt_pbkdf2_sha256`, `zupt_keccak`/SHA-3,
 *   `zupt_mlkem*`, `zupt_x25519`) operam apenas sobre estado fornecido pelo
 *   chamador, portanto podem ser usadas por threads simultâneas desde que cada
 *   thread tenha seu próprio contexto.
 * - Dois threads não devem compartilhar o mesmo `zupt_sha256_ctx`,
 *   `zupt_aes256_ctx` ou `zupt_keyring_t`: a biblioteca não faz nenhuma
 *   proteção interna.
 * - `zupt_keyring_t` embutido em `zupt_options_t` não deve ser passado por
 *   referência para duas threads que criptografam blocos diferentes, porque o
 *   `block_seq` que compõe o nonce é responsabilidade do chamador.
 *
 * # Exceções
 *
 * - `zupt_random_bytes()` consulta o kernel a cada chamada. É seguro quanto a
 *   dados, mas encerra o processo com `exit(1)` quando a fonte falha — um
 *   comportamento que nenhuma thread consegue tratar.
 * - `zupt_mlock_keys()` altera estado do processo, não da biblioteca. Chamar de
 *   várias threads sobre a mesma região é definido pelo kernel.
 * - As funções de arquivo (`zupt_disk_backup()`, `zupt_extract_archive()` e
 *   afins) dependem de `FILE *` e de `chdir`; a biblioteca não oferece
 *   mecanismo contra uso concorrente do diretório atual.
 *
 * @see \ref page-limitacoes para as funções declaradas sem definição.
 */
