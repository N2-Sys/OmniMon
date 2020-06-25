#ifndef __HASH_H__
#define __HASH_H__

#include <stdint.h>
#include <stdlib.h>

#define BIG_CONSTANT(x) (x##LLU)

uint64_t AwareHash(unsigned char* data, uint64_t n,
        uint64_t hash, uint64_t scale, uint64_t hardener);
uint64_t AwareHash_debug(unsigned char* data, uint64_t n,
        uint64_t hash, uint64_t scale, uint64_t hardener);

uint64_t GenHashSeed(int index);

int is_prime(int num);
int calc_next_prime(int num);

void mangle(const unsigned char* key, unsigned char* ret_key,
		int nbytes);

void unmangle(const unsigned char* key, unsigned char* ret_key,
		int nbytes);

uint64_t MurmurHash64A(const void * key, int len, uint64_t seed);

#endif