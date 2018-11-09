#ifndef _LAMPORT_H_
#define _LAMPORT_H_

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <openssl/sha.h>

#ifndef HASH_SIZE_BITS
#    define HASH_SIZE_BITS  256
#endif

#ifndef BYTE_SIZE
#    define BYTE_SIZE       8
#endif

#ifndef hashfunc
#    define hashfunc(x, y) sha256(x, y)
#endif

#ifndef hashfilefunc
#    define hashfilefunc(x, y, z) sha256file(x, y, z)
#endif

#define HASH_SIZE_BYTES (HASH_SIZE_BITS / BYTE_SIZE)

#define hashalgorithm "SHA-256"


#ifndef BUFSIZE
#    define BUFSIZE 1024
#endif

#ifndef RANDOMSRC
#    define RANDOMSRC "/dev/urandom"
#endif

/* Some global vars */

// Used during the work with base64
static uint8_t* bs64;
static size_t bs64len;

static char* progname; // Will point to argv[0]


/* Functions */
void panic(const char* s, const int code,
           const char* justonemorething);
void usage(const char* arg);

void sha256(uint8_t dst[HASH_SIZE_BYTES], const uint8_t src[HASH_SIZE_BYTES]);
void sha256file(const uint8_t* filename, uint8_t* hash);

void readkey(const uint8_t* filename,
             uint8_t keyarray[HASH_SIZE_BITS][2][HASH_SIZE_BYTES]);

#endif /* _LAMPORT_H_ */
