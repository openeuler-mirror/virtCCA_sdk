#ifndef __ATTESTATION_H_
#define __ATTESTATION_H_

#include <stddef.h>

#define TSI_SUCCESS 0


enum TSI_ERROR {
    NULL_INPUT = 0x00010001,  /* NULL pointer. */
    INVALID_PARAM,            /* Invalid param. */
    INSUFFICIENT_BUFFER_LEN,  /* Insufficient buffer space. */
    NO_DEVICE_FILE,           /* The TSI device file does not exist. */
    TSI_ERROR,                /* TSI error. */
};

typedef struct {
    int fd;
} tsi_ctx;

/*
 * @brief   Init ctx.
 * @return  TSI context
 */
tsi_ctx *tsi_new_ctx(void);

/*
 * @brief   Free ctx.
 * @param   ctx [IN] TSI context
 */
void tsi_free_ctx(tsi_ctx *ctx);

/*
 * @brief   Get TSI version.
 * @param   ctx [IN] TSI context
 * @param   major [OUT] Major version
 * @param   minor [OUT] Minor version
 * @return  TSI_SUCCESS SUCCESS
 *          TSI_ERROR ERROR
 */
int get_version(tsi_ctx *ctx, int *major, int *minor);

/*
 * @brief   Get attestation token.
 * @param   ctx [IN] TSI context
 * @param   challenge [IN] Challenge
 * @param   challenge_len [IN] Size of challenge. The maxinum value is 64.
 * @param   token [OUT] Attestation token
 * @param   token_len [IN/OUT] Size of attestation token
 * @return  TSI_SUCCESS Success
 *          For other error codes, see TSI_ERROR.
 */
int get_attestation_token(tsi_ctx *ctx, unsigned char *challenge, size_t challenge_len,
                          unsigned char *token, size_t *token_len);

/*
 * @brief   Get device cert.
 * @param   ctx [IN] TSI context
 * @param   dev_cert [OUT] Device cert buf
 * @param   dev_cert_len [IN/OUT] Size of device cert buf
 * @return  TSI_SUCCESS Success
 *          For other error codes, see TSI_ERROR.
 */
int get_dev_cert(tsi_ctx *ctx, unsigned char *dev_cert, size_t *dev_cert_len);

#endif  /* __ATTESTATION_H_ */
