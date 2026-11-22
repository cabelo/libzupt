/*
 * ZUPT - XXH64 Hash (based on xxHash by Yann Collet, BSD-2)
 */
/**
 * @cond PORT
 * @file  zupt_xxh.c
 * @brief Implementação do hash XXH64 (não criptográfico).
 * @details Calcula o digest de 64 bits do algoritmo XXH64, derivado do xxHash
 * de Yann Collet (licença BSD-2, citada no cabeçalho original). O
 * resultado é usado pela libzupt como verificação de integridade de
 * blocos e de arquivo (campo `checksum` de zupt_block_t e
 * `ZUPT_FLAG_CKSUM_XXH64`), e não como função de autenticação: XXH64
 * não resiste a colisões procuradas por um atacante, o que diferencia
 * seu papel do HMAC-SHA256 usado na cifra.
 *
 * O algoritmo processa a entrada em faixas de 32 bytes com quatro
 * acumuladores independentes quando o tamanho é maior ou igual a 32,
 * e um único hash inicial para entradas menores; as sobras são consumidas em trechos de
 * 8, 4 e 1 byte. A leitura dos dados usa `memcpy` de 8 e 4 bytes, o
 * que produz o resultado na endianidade nativa da máquina; este
 * módulo é portanto sensível à plataforma (diferentemente dos
 * helpers little-endian de include/zupt.h).
 * @endcond
 * @cond INGLES
 * @file  zupt_xxh.c
 * @brief Implementation of the XXH64 hash (non-cryptographic).
 * @details Computes the 64-bit digest of the XXH64 algorithm, derived from Yann
 * Collet's xxHash (BSD-2 license, cited in the original header). The
 * result is used by libzupt as an integrity check of
 * blocks and of files (the `checksum` field of zupt_block_t and
 * `ZUPT_FLAG_CKSUM_XXH64`), and not as an authentication function: XXH64
 * does not resist collisions sought by an attacker, which distinguishes
 * its role from the HMAC-SHA256 used in the cipher.
 *
 * The algorithm processes the input in 32-byte ranges with four
 * independent accumulators when the size is greater than or equal to 32,
 * and a single initial hash for smaller inputs; the remainder is consumed in chunks of
 * 8, 4 and 1 byte. Reading the data uses `memcpy` of 8 and 4 bytes, which
 * produces the result in the machine's native endianness; this
 * module is therefore platform-sensitive (unlike the
 * little-endian helpers in include/zupt.h).
 * @endcond */
#include "zupt.h"
#include <string.h>

/**
 * @cond PORT
 * @def   P1
 * @brief Constante multiplicativa 0x9E3779B185EBCA87 (11400714819323198487) do XXH64.
 * @details É o multiplicador das rodadas de acumulação: xround() o aplica
 * depois da rotação de 31 bits, e merge() o usa para diluir cada
 * acumulador no hash parcial. Também intervém na formação do estado
 * inicial dos quatro acumuladores (`seed + P1 + P2` e `seed - P1`)
 * e na mistura final das sobras de 8, 4 e 1 byte.
 * @note   Valor primo, escolhido no XXH64 original por boa difusão de bits
 * em multiplicações de 64×64; não possui significado secreto.
 * @endcond
 * @cond INGLES
 * @def   P1
 * @brief Multiplicative constant 0x9E3779B185EBCA87 (11400714819323198487) of XXH64.
 * @details It is the multiplier of the accumulation rounds: xround() applies it
 * after the 31-bit rotation, and merge() uses it to dilute each
 * accumulator into the partial hash. It also takes part in forming the
 * initial state of the four accumulators (`seed + P1 + P2` and `seed - P1`)
 * and in the final mixing of the 8-, 4- and 1-byte remainder.
 * @note   Prime value, chosen in the original XXH64 for good bit diffusion
 * in 64×64 multiplications; it has no secret meaning.
 * @endcond */
#define P1 0x9E3779B185EBCA87ULL
/**
 * @cond PORT
 * @def   P2
 * @brief Constante multiplicativa 0xC2B2AE3D27D4EB4F (14029467366897019727) do XXH64.
 * @details Multiplica a palavra de entrada dentro de xround() antes da
 * rotação, definindo como cada byte consumido afeta o acumulador.
 * Na etapa final de avalanche (aval) é o primeiro multiplicador,
 * aplicado após o deslocamento de 33 bits.
 * @note   Valor primo.
 * @endcond
 * @cond INGLES
 * @def   P2
 * @brief Multiplicative constant 0xC2B2AE3D27D4EB4F (14029467366897019727) of XXH64.
 * @details Multiplies the input word inside xround() before the
 * rotation, defining how each consumed byte affects the accumulator.
 * In the final avalanche stage (aval) it is the first multiplier,
 * applied after the 33-bit shift.
 * @note   Prime value.
 * @endcond */
#define P2 0xC2B2AE3D27D4EB4FULL
/**
 * @cond PORT
 * @def   P3
 * @brief Constante multiplicativa 0x165667B19E3779F9 (16098980100592839161) do XXH64.
 * @details Segundo multiplicador de aval(): aplicado após o deslocamento de
 * 29 bits, fechando a cadeia de avalanche antes do xor final de 32
 * bits. Também aparece na mistura das sobras de 4 bytes de
 * zupt_xxh64().
 * @note   Valor primo.
 * @endcond
 * @cond INGLES
 * @def   P3
 * @brief Multiplicative constant 0x165667B19E3779F9 (16098980100592839161) of XXH64.
 * @details Second multiplier of aval(): applied after the 29-bit shift, closing
 * the avalanche chain before the final 32-bit xor. It also
 * appears in the mixing of the 4-byte remainder of zupt_xxh64().
 * @note   Prime value.
 * @endcond */
#define P3 0x165667B19E3779F9ULL
/**
 * @cond PORT
 * @def   P4
 * @brief Constante multiplicativa 0x85EBCA77C2B2AE63 (9650029242287828579) do XXH64.
 * @details Parcela aditiva de merge() e da mistura das sobras de 8 bytes.
 * Somar uma constante após a multiplicação evita que combinações
 * simétricas de acumuladores produzam o mesmo hash parcial.
 * @note   Valor primo.
 * @endcond
 * @cond INGLES
 * @def   P4
 * @brief Multiplicative constant 0x85EBCA77C2B2AE63 (9650029242287828579) of XXH64.
 * @details Additive term of merge() and of the mixing of the 8-byte remainder.
 * Adding a constant after the multiplication prevents symmetric
 * combinations of accumulators from producing the same partial hash.
 * @note   Prime value.
 * @endcond */
#define P4 0x85EBCA77C2B2AE63ULL
/**
 * @cond PORT
 * @def   P5
 * @brief Constante multiplicativa 0x27D4EB2F165667C5 (2839462366807629765) do XXH64.
 * @details Inicializa o hash parcial quando a entrada tem menos de 32 bytes
 * (`seed + P5`) e multiplica cada byte individual da última sobra de
 * 1 byte. Não participa das rodadas de 32 bytes.
 * @note   Valor primo.
 * @endcond
 * @cond INGLES
 * @def   P5
 * @brief Multiplicative constant 0x27D4EB2F165667C5 (2839462366807629765) of XXH64.
 * @details Initializes the partial hash when the input is shorter than 32 bytes
 * (`seed + P5`) and multiplies each individual byte of the last
 * 1-byte remainder. It does not take part in the 32-byte rounds.
 * @note   Prime value.
 * @endcond */
#define P5 0x27D4EB2F165667C5ULL

/**
 * @cond PORT
 * @brief Rotação circular à esquerda de uma palavra de 64 bits.
 * @param[in] x Valor de 64 bits a rotacionar.
 * @param[in] r Número de posições de rotação (usado com 1..63).
 * @return Palavra rotacionada.
 * @endcond
 * @cond INGLES
 * @brief Circular left rotation of a 64-bit word.
 * @param[in] x 64-bit value to rotate.
 * @param[in] r Number of rotation positions (used with 1..63).
 * @return Rotated word.
 * @endcond */
static inline uint64_t rotl64(uint64_t x,int r){return(x<<r)|(x>>(64-r));}
/**
 * @cond PORT
 * @brief Lê 8 bytes da memória e devolve como palavra de 64 bits.
 * @details Usa `memcpy` para não exigir alinhamento do ponteiro; a palavra
 * resultante segue a endianidade nativa da plataforma.
 * @param[in] p Leitura de 8 bytes a partir deste endereço.
 * @return Palavra de 64 bits lida.
 * @endcond
 * @cond INGLES
 * @brief Reads 8 bytes from memory and returns them as a 64-bit word.
 * @details Uses `memcpy` so as not to require alignment of the pointer; the resulting
 * word follows the platform's native endianness.
 * @param[in] p Read 8 bytes starting at this address.
 * @return 64-bit word read.
 * @endcond */
static inline uint64_t r64(const uint8_t*p){uint64_t v;memcpy(&v,p,8);return v;}
/**
 * @cond PORT
 * @brief Lê 4 bytes da memória e devolve como palavra de 32 bits.
 * @details Igual a r64, com largura de 4 bytes; endianidade nativa.
 * @param[in] p Leitura de 4 bytes a partir deste endereço.
 * @return Palavra de 32 bits lida.
 * @endcond
 * @cond INGLES
 * @brief Reads 4 bytes from memory and returns them as a 32-bit word.
 * @details Same as r64, with a width of 4 bytes; native endianness.
 * @param[in] p Read 4 bytes starting at this address.
 * @return 32-bit word read.
 * @endcond */
static inline uint32_t r32(const uint8_t*p){uint32_t v;memcpy(&v,p,4);return v;}
/**
 * @cond PORT
 * @brief Rodada de acumulador: mistura um bloco de 64 bits ao estado parcial.
 * @details Computa `rotl64(a + i*P2, 31) * P1`.
 * @param[in] a Valor parcial anterior.
 * @param[in] i Palavra de entrada (ou palavra de entrada expandida).
 * @return Estado parcial misturado.
 * @endcond
 * @cond INGLES
 * @brief Accumulator round: mixes a 64-bit block into the partial state.
 * @details Computes `rotl64(a + i*P2, 31) * P1`.
 * @param[in] a Previous partial value.
 * @param[in] i Input word (or expanded input word).
 * @return Mixed partial state.
 * @endcond */
static inline uint64_t xround(uint64_t a,uint64_t i){return rotl64(a+i*P2,31)*P1;}
/**
 * @cond PORT
 * @brief Combina um acumulador parcial com o hash em construção.
 * @details Computa `(a ^ xround(0, v)) * P1 + P4`; a chamada com `v` zero
 * produz a dobra de entrada usada nas etapas de mistura final.
 * @param[in] a Hash parcial em construção.
 * @param[in] v Acumulador parcial a incorporar.
 * @return Hash parcial atualizado.
 * @endcond
 * @cond INGLES
 * @brief Combines a partial accumulator with the hash under construction.
 * @details Computes `(a ^ xround(0, v)) * P1 + P4`; the call with `v` zero
 * produces the input folding used in the final mixing stages.
 * @param[in] a Partial hash under construction.
 * @param[in] v Partial accumulator to incorporate.
 * @return Updated partial hash.
 * @endcond */
static inline uint64_t merge(uint64_t a,uint64_t v){return(a^xround(0,v))*P1+P4;}
/**
 * @cond PORT
 * @brief Etapa final de avalanche do XXH64.
 * @details Aplica a sequência de xor-shift e multiplicações
 * (`h ^= h>>33; h *= P2; h ^= h>>29; h *= P3; h ^= h>>32`) que
 * distribui as diferenças de bits por todo o resultado.
 * @param[in] h Hash parcial antes do avalanche.
 * @return Digest final de 64 bits.
 * @endcond
 * @cond INGLES
 * @brief Final avalanche stage of XXH64.
 * @details Applies the sequence of xor-shifts and multiplications
 * (`h ^= h>>33; h *= P2; h ^= h>>29; h *= P3; h ^= h>>32`) that
 * spreads bit differences throughout the result.
 * @param[in] h Partial hash before the avalanche.
 * @return Final 64-bit digest.
 * @endcond */
static inline uint64_t aval(uint64_t h){h^=h>>33;h*=P2;h^=h>>29;h*=P3;h^=h>>32;return h;}

/**
 * @cond PORT
 * @brief Calcula o digest XXH64 de um buffer.
 * @details Para `len >= 32` a entrada é lida em faixas de 32 bytes,
 * mantendo quatro acumuladores inicializados a partir do seed e das
 * constantes P1/P2; os acumuladores são então combinados com merge.
 * Para `len < 32` o hash parcial inicial é `seed + P5`. Em ambos os
 * casos o comprimento é somado ao hash parcial e as sobras são
 * processadas em trechos de 8, 4 e 1 byte antes do avalanche final.
 * @param[in] data Buffer a hashizar; pode ser NULL apenas se `len` for 0.
 * @param[in] len  Quantidade de bytes a hashizar.
 * @param[in] seed Semente que parametriza o hash (chamadas com seeds
 * diferentes produzem resultados distintos para a mesma entrada).
 * @return Digest de 64 bits.
 * @note Não é uma função de autenticação: serve a verificações de integridade
 * contra corrupção acidental. A função não produz erro.
 * @see ZUPT_FLAG_CKSUM_XXH64, zupt_block_t::checksum
 * @endcond
 * @cond INGLES
 * @brief Computes the XXH64 digest of a buffer.
 * @details For `len >= 32` the input is read in 32-byte ranges,
 * keeping four accumulators initialized from the seed and the
 * constants P1/P2; the accumulators are then combined with merge.
 * For `len < 32` the initial partial hash is `seed + P5`. In both
 * cases the length is added to the partial hash and the remainder is
 * processed in chunks of 8, 4 and 1 byte before the final avalanche.
 * @param[in] data Buffer to hash; may be NULL only if `len` is 0.
 * @param[in] len  Number of bytes to hash.
 * @param[in] seed Seed that parameterizes the hash (calls with different
 * seeds produce different results for the same input).
 * @return 64-bit digest.
 * @note It is not an authentication function: it serves integrity checks
 * against accidental corruption. The function does not produce errors.
 * @see ZUPT_FLAG_CKSUM_XXH64, zupt_block_t::checksum
 * @endcond */
uint64_t zupt_xxh64(const void*data,size_t len,uint64_t seed){
    const uint8_t*p=(const uint8_t*)data,*end=p+len;
    uint64_t h;
    if(len>=32){
        const uint8_t*lim=end-32;
        uint64_t v1=seed+P1+P2,v2=seed+P2,v3=seed,v4=seed-P1;
        do{v1=xround(v1,r64(p));p+=8;v2=xround(v2,r64(p));p+=8;
           v3=xround(v3,r64(p));p+=8;v4=xround(v4,r64(p));p+=8;}while(p<=lim);
        h=rotl64(v1,1)+rotl64(v2,7)+rotl64(v3,12)+rotl64(v4,18);
        h=merge(h,v1);h=merge(h,v2);h=merge(h,v3);h=merge(h,v4);
    }else{h=seed+P5;}
    h+=(uint64_t)len;
    while(p+8<=end){h^=xround(0,r64(p));h=rotl64(h,27)*P1+P4;p+=8;}
    if(p+4<=end){h^=(uint64_t)r32(p)*P1;h=rotl64(h,23)*P2+P3;p+=4;}
    while(p<end){h^=(*p)*P5;h=rotl64(h,11)*P1;p++;}
    return aval(h);
}
