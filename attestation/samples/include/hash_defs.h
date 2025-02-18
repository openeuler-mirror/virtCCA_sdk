#ifndef HASH_DEFS_H
#define HASH_DEFS_H

/* If the OpenSSL header file is available, use its definition */
#ifdef OPENSSL_SHA_H
#include <openssl/sha.h>
#else
/* Otherwise use our own definition */
#define SHA1_DIGEST_LENGTH   20
#define SHA256_DIGEST_LENGTH 32
#define SHA384_DIGEST_LENGTH 38
#define SHA512_DIGEST_LENGTH 64
#endif

#endif /* HASH_DEFS_H */