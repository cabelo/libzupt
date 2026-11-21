/*
 * ZUPT - XXH64 Hash (based on xxHash by Yann Collet, BSD-2)
 */
/**
 * @file  zupt_xxh.c
 * @brief Implementação do hash XXH64 (não criptográfico).
 * @details Calcula o digest de 64 bits do algoritmo XXH64, derivado do xxHash
 *          de Yann Collet (licença BSD-2, citada no cabeçalho original). O
 *          resultado é usado pela libzupt como verificação de integridade de
 *          blocos e de arquivo (campo `checksum` de zupt_block_t e
 *          `ZUPT_FLAG_CKSUM_XXH64`), e não como função de autenticação: XXH64
 *          não resiste a colisões procuradas por um atacante, o que diferencia
 *          seu papel do HMAC-SHA256 usado na cifra.
 *
 *          O algoritmo processa a entrada em faixas de 32 bytes com quatro
 *          acumuladores independentes quando o tamanho é maior ou igual a 32,
 *          e um único hash inicial para entradas menores; as sobras são consumidas em trechos de
 *          8, 4 e 1 byte. A leitura dos dados usa `memcpy` de 8 e 4 bytes, o
 *          que produz o resultado na endianidade nativa da máquina; este
 *          módulo é portanto sensível à plataforma (diferentemente dos
 *          helpers little-endian de include/zupt.h).
 */
#include "zupt.h"
#include <string.h>

/**
 * @def   P1
 * @brief Constante multiplicativa 0x9E3779B185EBCA87 (11400714819323198487) do XXH64.
 * @details É o multiplicador das rodadas de acumulação: xround() o aplica
 *          depois da rotação de 31 bits, e merge() o usa para diluir cada
 *          acumulador no hash parcial. Também intervém na formação do estado
 *          inicial dos quatro acumuladores (`seed + P1 + P2` e `seed - P1`)
 *          e na mistura final das sobras de 8, 4 e 1 byte.
 * @note   Valor primo, escolhido no XXH64 original por boa difusão de bits
 *         em multiplicações de 64×64; não possui significado secreto.
 */
#define P1 0x9E3779B185EBCA87ULL
/**
 * @def   P2
 * @brief Constante multiplicativa 0xC2B2AE3D27D4EB4F (14029467366897019727) do XXH64.
 * @details Multiplica a palavra de entrada dentro de xround() antes da
 *          rotação, definindo como cada byte consumido afeta o acumulador.
 *          Na etapa final de avalanche (aval) é o primeiro multiplicador,
 *          aplicado após o deslocamento de 33 bits.
 * @note   Valor primo.
 */
#define P2 0xC2B2AE3D27D4EB4FULL
/**
 * @def   P3
 * @brief Constante multiplicativa 0x165667B19E3779F9 (16098980100592839161) do XXH64.
 * @details Segundo multiplicador de aval(): aplicado após o deslocamento de
 *          29 bits, fechando a cadeia de avalanche antes do xor final de 32
 *          bits. Também aparece na mistura das sobras de 4 bytes de
 *          zupt_xxh64().
 * @note   Valor primo.
 */
#define P3 0x165667B19E3779F9ULL
/**
 * @def   P4
 * @brief Constante multiplicativa 0x85EBCA77C2B2AE63 (9650029242287828579) do XXH64.
 * @details Parcela aditiva de merge() e da mistura das sobras de 8 bytes.
 *          Somar uma constante após a multiplicação evita que combinações
 *          simétricas de acumuladores produzam o mesmo hash parcial.
 * @note   Valor primo.
 */
#define P4 0x85EBCA77C2B2AE63ULL
/**
 * @def   P5
 * @brief Constante multiplicativa 0x27D4EB2F165667C5 (2839462366807629765) do XXH64.
 * @details Inicializa o hash parcial quando a entrada tem menos de 32 bytes
 *          (`seed + P5`) e multiplica cada byte individual da última sobra de
 *          1 byte. Não participa das rodadas de 32 bytes.
 * @note   Valor primo.
 */
#define P5 0x27D4EB2F165667C5ULL

/**
 * @brief Rotação circular à esquerda de uma palavra de 64 bits.
 * @param[in] x Valor de 64 bits a rotacionar.
 * @param[in] r Número de posições de rotação (usado com 1..63).
 * @return Palavra rotacionada.
 */
static inline uint64_t rotl64(uint64_t x,int r){return(x<<r)|(x>>(64-r));}
/**
 * @brief Lê 8 bytes da memória e devolve como palavra de 64 bits.
 * @details Usa `memcpy` para não exigir alinhamento do ponteiro; a palavra
 *          resultante segue a endianidade nativa da plataforma.
 * @param[in] p Leitura de 8 bytes a partir deste endereço.
 * @return Palavra de 64 bits lida.
 */
static inline uint64_t r64(const uint8_t*p){uint64_t v;memcpy(&v,p,8);return v;}
/**
 * @brief Lê 4 bytes da memória e devolve como palavra de 32 bits.
 * @details Igual a r64, com largura de 4 bytes; endianidade nativa.
 * @param[in] p Leitura de 4 bytes a partir deste endereço.
 * @return Palavra de 32 bits lida.
 */
static inline uint32_t r32(const uint8_t*p){uint32_t v;memcpy(&v,p,4);return v;}
/**
 * @brief Rodada de acumulador: mistura um bloco de 64 bits ao estado parcial.
 * @details Computa `rotl64(a + i*P2, 31) * P1`.
 * @param[in] a Valor parcial anterior.
 * @param[in] i Palavra de entrada (ou palavra de entrada expandida).
 * @return Estado parcial misturado.
 */
static inline uint64_t xround(uint64_t a,uint64_t i){return rotl64(a+i*P2,31)*P1;}
/**
 * @brief Combina um acumulador parcial com o hash em construção.
 * @details Computa `(a ^ xround(0, v)) * P1 + P4`; a chamada com `v` zero
 *          produz a dobra de entrada usada nas etapas de mistura final.
 * @param[in] a Hash parcial em construção.
 * @param[in] v Acumulador parcial a incorporar.
 * @return Hash parcial atualizado.
 */
static inline uint64_t merge(uint64_t a,uint64_t v){return(a^xround(0,v))*P1+P4;}
/**
 * @brief Etapa final de avalanche do XXH64.
 * @details Aplica a sequência de xor-shift e multiplicações
 *          (`h ^= h>>33; h *= P2; h ^= h>>29; h *= P3; h ^= h>>32`) que
 *          distribui as diferenças de bits por todo o resultado.
 * @param[in] h Hash parcial antes do avalanche.
 * @return Digest final de 64 bits.
 */
static inline uint64_t aval(uint64_t h){h^=h>>33;h*=P2;h^=h>>29;h*=P3;h^=h>>32;return h;}

/**
 * @brief Calcula o digest XXH64 de um buffer.
 * @details Para `len >= 32` a entrada é lida em faixas de 32 bytes,
 *          mantendo quatro acumuladores inicializados a partir do seed e das
 *          constantes P1/P2; os acumuladores são então combinados com merge.
 *          Para `len < 32` o hash parcial inicial é `seed + P5`. Em ambos os
 *          casos o comprimento é somado ao hash parcial e as sobras são
 *          processadas em trechos de 8, 4 e 1 byte antes do avalanche final.
 * @param[in] data Buffer a hashizar; pode ser NULL apenas se `len` for 0.
 * @param[in] len  Quantidade de bytes a hashizar.
 * @param[in] seed Semente que parametriza o hash (chamadas com seeds
 *                 diferentes produzem resultados distintos para a mesma entrada).
 * @return Digest de 64 bits.
 * @note Não é uma função de autenticação: serve a verificações de integridade
 *       contra corrupção acidental. A função não produz erro.
 * @see ZUPT_FLAG_CKSUM_XXH64, zupt_block_t::checksum
 */
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
