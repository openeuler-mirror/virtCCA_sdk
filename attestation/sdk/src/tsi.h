#ifndef __TSI_H_
#define __TSI_H_

#include <linux/ioctl.h>

#define TSI_MAGIC 'T'


/* Size in bytes of the SHA512 measurement */
#define SHA512_SIZE                (64U)

/* Size in bytes of the SHA256 measurement */
#define SHA256_SIZE                (32U)

/*
 * Size in bytes of the largest measurement type that can be supported.
 * This macro needs to be updated accordingly if new algorithms are supported.
 */
#define MAX_MEASUREMENT_SIZE       SHA512_SIZE
#define MAX_DEV_CERT_SIZE          (4096U)

#define GRANULE_SIZE               (4096U)
#define MAX_TOKEN_GRANULE_COUNT    (2U)
#define CHALLENGE_SIZE             (64U)

typedef struct cvm_measurement {
    int index;
    unsigned char value[MAX_MEASUREMENT_SIZE];
} cvm_measurement_t;

typedef struct cvm_tsi_version {
    int major;
    int minor;
} cvm_tsi_version_t;

typedef struct cvm_attestation_cmd {
    unsigned char challenge[CHALLENGE_SIZE]; /* input: challenge value */
    unsigned char token[GRANULE_SIZE * MAX_TOKEN_GRANULE_COUNT];
    unsigned long token_size; /* return: token size */
} cvm_attestation_cmd_t;

typedef struct cca_dev_cert {
    unsigned long size;
    unsigned char value[MAX_DEV_CERT_SIZE];
} cca_dev_cert_t;

#define TMM_GET_TSI_VERSION _IOR(TSI_MAGIC, 0, cvm_tsi_version_t)

#define TMM_GET_ATTESTATION_TOKEN _IOWR(TSI_MAGIC, 1, cvm_attestation_cmd_t)

#define TMM_GET_DEV_CERT _IOR(TSI_MAGIC, 2, cca_dev_cert_t)

#endif  /* __TSI_H_ */
