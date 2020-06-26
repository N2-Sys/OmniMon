#include <stdio.h>
#include "include/hash.h"

uint64_t AwareHash(unsigned char* data, uint64_t n,
        uint64_t hash, uint64_t scale, uint64_t hardener) {

	while (n) {
		hash *= scale;
		hash += *data++;
		n--;
	}
	return hash ^ hardener;
}


uint64_t AwareHash_debug(unsigned char* data, uint64_t n,
        uint64_t hash, uint64_t scale, uint64_t hardener) {

	while (n) {
        fprintf(stderr, "    %lu %lu %lu %u\n", n, hash, scale, *data);
		hash *= scale;
		hash += *data++;
		n--;
        fprintf(stderr, "        internal %lu\n", hash);
	}
	return hash ^ hardener;
}

/*
 * mangle
 */
// void mangle(const unsigned char* key, unsigned char* ret_key,
// 		int nbytes) {
// 	unsigned long long new_key = 0;
// 	int i;
// 	for (i=0; i<nbytes; ++i) {
// 		new_key |= key[nbytes-i-1] << (i * 8);
// 	}
// 	new_key = (new_key * 2083697005) & (0xffffffff);
// 	for (i=0; i<nbytes; ++i) {
// 		ret_key[i] = (new_key >> (i * 8)) & 0xff;
// 	}
// }
//
/*
 * mangle
 */
// void unmangle(const unsigned char* key, unsigned char* ret_key,
// 		int nbytes) {
// 	/*
// 	 * 10001^-1 mod 2^32 = 3472992753
// 	 * 1001^-1 mod 2^32 = 3054961753
// 	 * 101^-1 mod 2^32 = 2083697005
// 	 */
// 	unsigned long long new_key = 0;
// 	int i;
// 	for (i=0; i<nbytes; ++i) {
// 		new_key |= key[i] << (i * 8);
// 	}
// 	new_key = (new_key * 101) & (0xffffffff);
// 	for (i=0; i<nbytes; ++i) {
// 		ret_key[nbytes-i-1] = (new_key >> (i * 8)) & 0xff;
// 	}
// }

void mangle(const unsigned char* key, unsigned char* ret_key,
		int nbytes) {
	for (int i=0; i<nbytes; ++i) {
		ret_key[i] = key[nbytes-i-1];
	}

    if (nbytes == 13) {
		ret_key[0] = key[5];
		ret_key[1] = key[11];
		ret_key[2] = key[7];
		ret_key[3] = key[6];
		ret_key[4] = key[1];
		ret_key[5] = key[9];
		ret_key[6] = key[10];
		ret_key[7] = key[4];
		ret_key[8] = key[2];
		ret_key[9] = key[8];
		ret_key[10] = key[12];
		ret_key[11] = key[0];
		ret_key[12] = key[3];
    }
}

void unmangle(const unsigned char* key, unsigned char* ret_key,
		int nbytes) {
	for (int i=0; i<nbytes; ++i) {
		ret_key[i] = key[nbytes-i-1];
	}

    if (nbytes == 13) {
		ret_key[0] = key[11];
		ret_key[1] = key[4];
		ret_key[2] = key[8];
		ret_key[3] = key[12];
		ret_key[4] = key[7];
		ret_key[5] = key[0];
		ret_key[6] = key[3];
		ret_key[7] = key[2];
		ret_key[8] = key[9];
		ret_key[9] = key[5];
		ret_key[10] = key[6];
		ret_key[11] = key[1];
		ret_key[12] = key[10];
    }
}

// void unmangle(const unsigned char* key, unsigned char* ret_key,
// 		int nbytes) {
// 	/*
// 	 * 10001^-1 mod 2^32 = 3472992753
// 	 * 1001^-1 mod 2^32 = 3054961753
// 	 * 101^-1 mod 2^32 = 2083697005
// 	 */
// 	unsigned long long new_key = 0;
// 	int i;
// 	for (i=0; i<nbytes; ++i) {
// 		new_key |= key[i] << (i * 8);
// 	}
// 	new_key = (new_key * 101) & (0xffffffff);
// 	for (i=0; i<nbytes; ++i) {
// 		ret_key[nbytes-i-1] = (new_key >> (i * 8)) & 0xff;
// 	}
// }


uint64_t seed = 0;
uint64_t GenHashSeed(int index) {
    /*
    if (index == 0) {
        srand(0);
    }
    */
    if (seed == 0) {
        seed = rand();
    }
    uint64_t x, y = seed + index;
    mangle((const unsigned char*)&y, (unsigned char*)&x, 8);
    return AwareHash((uint8_t*)&y, 8, 388650253, 388650319, 1176845762);
}

int is_prime(int num) {
    int i;
    for (i=2; i<num; i++) {
        if ((num % i) == 0) {
            break;
        }
    }
    if (i == num) {
        return 1;
    }
    return 0;
}

int calc_next_prime(int num) {
    while (!is_prime(num)) {
        num++;
    }
    return num;
}

//-----------------------------------------------------------------------------
// MurmurHash2, 64-bit versions, by Austin Appleby
// The same caveats as 32-bit MurmurHash2 apply here - beware of alignment
// and endian-ness issues if used across multiple platforms.
// 64-bit hash for 64-bit platforms
uint64_t MurmurHash64A ( const void * key, int len, uint64_t seed )
{
	const uint64_t m = BIG_CONSTANT(0xc6a4a7935bd1e995);
	const int r = 47;

	uint64_t h = seed ^ (len * m);

	const uint64_t * data = (const uint64_t *)key;
	const uint64_t * end = data + (len/8);

	while(data != end)
	{
		uint64_t k = *data++;

		k *= m;
		k ^= k >> r;
		k *= m;

		h ^= k;
		h *= m;
	}

	const unsigned char * data2 = (const unsigned char*)data;

	switch(len & 7)
	{
		case 7: h ^= (uint64_t)(data2[6]) << 48;
		case 6: h ^= (uint64_t)(data2[5]) << 40;
		case 5: h ^= (uint64_t)(data2[4]) << 32;
		case 4: h ^= (uint64_t)(data2[3]) << 24;
		case 3: h ^= (uint64_t)(data2[2]) << 16;
		case 2: h ^= (uint64_t)(data2[1]) << 8;
		case 1: h ^= (uint64_t)(data2[0]);
			h *= m;
	};

	h ^= h >> r;
	h *= m;
	h ^= h >> r;

	return h;
}
