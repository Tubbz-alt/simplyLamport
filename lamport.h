#ifndef _LAMPORT_H_
#define _LAMPORT_H_

#define PASTER(x, y) x ## y
#define EVALUATOR(x, y) PASTER(x, y)

#define BYTE_SIZE       8 // bits
#define HASH_SIZE_BITS hashSizeBits
#define HASH_SIZE_BYTES (HASH_SIZE_BITS / BYTE_SIZE)
extern int hashSizeBits;

// Size of a private key
#define PVKSIZE (HASH_SIZE_BITS * HASH_SIZE_BYTES * 2)
// Size of a public key
#define PBKSIZE (HASH_SIZE_BITS * HASH_SIZE_BYTES * 2)
// Size of a signature
#define SIGNSIZE (HASH_SIZE_BITS * HASH_SIZE_BYTES)

#define RANDOMSRC "/dev/urandom"

#include <stdint.h>
#include <stdio.h> // fopen(), used to open RANDOMSRC,
                   // but this will be changed to a CSPRNG

/* Functions */

int genpvk(uint8_t privkey[HASH_SIZE_BITS][2][HASH_SIZE_BYTES]);

void sign(const uint8_t privkey[HASH_SIZE_BITS][2][HASH_SIZE_BYTES],
          const uint8_t hash[HASH_SIZE_BYTES],
          uint8_t signature[HASH_SIZE_BITS * HASH_SIZE_BYTES]);

int verify(const uint8_t pubkey[HASH_SIZE_BITS][2][HASH_SIZE_BYTES],
           const uint8_t hash[HASH_SIZE_BYTES],
           const uint8_t signature[HASH_SIZE_BITS * HASH_SIZE_BYTES],
           void (*hashfunc)(uint8_t dst[HASH_SIZE_BYTES],
                            const uint8_t src[HASH_SIZE_BYTES]));

void public(const uint8_t privkey[HASH_SIZE_BITS][2][HASH_SIZE_BYTES],
            uint8_t pubkey[HASH_SIZE_BITS][2][HASH_SIZE_BYTES],
            void (*hashfunc)(uint8_t dst[HASH_SIZE_BYTES],
                             const uint8_t src[HASH_SIZE_BYTES]));

#endif /* _LAMPORT_H_ */
