#ifndef _MAIN_H_
#define _MAIN_H_

#define PASTER(x, y) x ## y
#define EVALUATOR(x, y) PASTER(x, y)
#define STR_EXPAND(macro) #macro
#define STR(macro) STR_EXPAND(macro)

// Determines the size of the buffer used in HASHFILE()
#ifndef BUFSIZE
#    define BUFSIZE 1024
#endif

#ifndef HASHALGO
#    define HASHALGO SHA256
#endif
#define HASHALGOSTR STR(HASHALGO)

#include "lamport.h"

/* Just one global var */
static char* progname; // Will point to argv[0]

void usage(const char* s);
void panic(const char* s, const int code,
           const char* justonemorething);
void readkey(const uint8_t* filename,
             uint8_t keyarray[HASH_SIZE_BITS][2][HASH_SIZE_BYTES]);
void tofile(const uint8_t* const data,
            const uint8_t* const filename,
            const size_t len);

void HASH(uint8_t dst[HASH_SIZE_BYTES], const uint8_t src[HASH_SIZE_BYTES]);
void HASHFILE(const uint8_t* const filename, uint8_t hash[HASH_SIZE_BYTES]);

#endif /* _MAIN_H_ */
