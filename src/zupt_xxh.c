/*
 * ZUPT - XXH64 Hash (based on xxHash by Yann Collet, BSD-2)
 */
#include "zupt.h"
#include <string.h>

#define P1 0x9E3779B185EBCA87ULL
#define P2 0xC2B2AE3D27D4EB4FULL
#define P3 0x165667B19E3779F9ULL
#define P4 0x85EBCA77C2B2AE63ULL
#define P5 0x27D4EB2F165667C5ULL

static inline uint64_t rotl64(uint64_t x,int r){return(x<<r)|(x>>(64-r));}
static inline uint64_t r64(const uint8_t*p){uint64_t v;memcpy(&v,p,8);return v;}
static inline uint32_t r32(const uint8_t*p){uint32_t v;memcpy(&v,p,4);return v;}
static inline uint64_t xround(uint64_t a,uint64_t i){return rotl64(a+i*P2,31)*P1;}
static inline uint64_t merge(uint64_t a,uint64_t v){return(a^xround(0,v))*P1+P4;}
static inline uint64_t aval(uint64_t h){h^=h>>33;h*=P2;h^=h>>29;h*=P3;h^=h>>32;return h;}

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
