#ifndef TOKEN_PARSE_H
#define TOKEN_PARSE_H

#include "qcbor/qcbor.h"
#include "qcbor/qcbor_spiffy_decode.h"

#define ATTEST_MAX_TOKEN_SIZE 4096

#define TAG_CCA_TOKEN                       (399)
#define CCA_PLAT_TOKEN                      (44234)
#define CCA_CVM_TOKEN                       (44241)

#define CCA_CVM_CHALLENGE                   (10)
#define CCA_CVM_PERSONALIZATION_VALUE       (44235)
#define CCA_CVM_HASH_ALGO_ID                (44236)
#define CCA_CVM_PUB_KEY                     (44237)
#define CCA_CVM_INITIAL_MEASUREMENT         (44238)
#define CCA_CVM_EXTENSIBLE_MEASUREMENTS     (44239)
#define CCA_CVM_EXTED_MEAS_SLOTS_NUM        (4)
#define CCA_CVM_PUB_KEY_HASH_ALGO_ID        (44240)

#define CCA_BYTE_SIZE_32    (32)
#define CCA_BYTE_SIZE_48    (48)
#define CCA_BYTE_SIZE_64    (64)

#define CCA_BYTE_SIZE_33    (33)
#define CCA_BYTE_SIZE_97    (97)

#define CCA_BYTE_SIZE_550   (550)

#define VIRTCCA_SUCCESS     (0)
#define VIRTCCA_ERROR       (1)

#define CCA_CVM_CLAIM_CNT   (7)

typedef struct q_useful_buf_c qbuf_t;

/*
 * DEN0137 Realm Management Monitor Specification (1.0-eac5)
 *
 * CCA attestation token {                     // Tag: 399 (cca-token-collection)
 *     CVM token {                             // 44241
 *         COSE_Sign1 envelop {                // 18 (COSE_Sign1)
 *             Protected headers
 *             Unprotected headers
 *             CVM token claim map {           // Payload
 *                 challenge                   // 10
 *                 rpv                         // 44235
 *                 rim                         // 44238
 *                 rem[4]                      // 44239
 *                 cvm_hash_algo_id            // 44236
 *                 pub_key                     // 44237
 *                 pub_key_hash_algo_id        // 44240
 *             }
 *             Signature(RAK)
 *         }
 *     }
 * }
*/

typedef struct {
    qbuf_t component_type; /* t */
    qbuf_t measurement; /* b */
    qbuf_t version; /* t */
    qbuf_t signer_id; /* b */
    qbuf_t hash_algo_id; /* t */
} sw_comp_claims_t;

typedef struct {
    qbuf_t challenge;                   /* 10 */
    qbuf_t rpv;                         /* 44235 */
    qbuf_t rim;                         /* 44238 */
    qbuf_t rem[4];                      /* 44239 */
    qbuf_t hash_algo_id;                /* 44236 */
    qbuf_t pub_key;                     /* 44237 */
    qbuf_t pub_key_hash_algo_id;        /* 44240 */
} cvm_claims_t;

typedef struct {
    qbuf_t p_headers;
    qbuf_t np_headers;
    qbuf_t payload;
    qbuf_t signature;
} cose_sign1_envelop_t;

typedef struct {
    cose_sign1_envelop_t cvm_envelop;
    qbuf_t               cvm_cose;
    cvm_claims_t         cvm_token;
} cca_token_t;

uint64_t parse_cca_attestation_token(cca_token_t *token,
                                     uint8_t *raw_token, size_t raw_token_size);
void print_cca_attestation_token(const cca_token_t *token);
void print_cca_attestation_token_raw(const cca_token_t *token);

#endif /* TOKEN_PARSE_H */