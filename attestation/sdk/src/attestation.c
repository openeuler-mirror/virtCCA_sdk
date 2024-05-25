#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>

#include "attestation.h"
#include "tsi.h"

tsi_ctx *tsi_new_ctx(void)
{
    tsi_ctx *ctx = malloc(sizeof(tsi_ctx));
    if (ctx == NULL) {
        return NULL;
    }
    ctx->fd = open("/dev/tsi", O_RDWR | O_CLOEXEC);
    if (ctx->fd == -1) {
        printf("Failed to open dev. errno: %d\n", errno);
        free(ctx);
        return NULL;
    }
    return ctx;
}

void tsi_free_ctx(tsi_ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    close(ctx->fd);
    free(ctx);
}

int get_version(tsi_ctx *ctx, int *major, int *minor)
{
    int ret;
    cvm_tsi_version_t version;

    if (ctx == NULL || major == NULL || minor == NULL) {
        return NULL_INPUT;
    }

    ret = ioctl(ctx->fd, TMM_GET_TSI_VERSION, &version);
    if (ret != 0) {
        printf("Failed to get TSI version. errno: %d\n", errno);
        return TSI_ERROR;
    }
    *major = version.major;
    *minor = version.minor;
    return TSI_SUCCESS;
}

int get_attestation_token(tsi_ctx *ctx, unsigned char *challenge, size_t challenge_len,
                          unsigned char *token, size_t *token_len)
{
    int ret;
    ssize_t read_len;
    cvm_attestation_cmd_t user_cmd = {0};

    if (ctx == NULL || challenge == NULL || token == NULL) {
        return NULL_INPUT;
    }
    if (challenge_len > CHALLENGE_SIZE) {
        printf("challenge too long.\n");
        return INVALID_PARAM;
    }

    strncpy(user_cmd.challenge, challenge, challenge_len);

    ret = ioctl(ctx->fd, TMM_GET_ATTESTATION_TOKEN, &user_cmd);
    if (ret != 0) {
        printf("Failed to get attestation token. errno: %d\n", errno);
        return TSI_ERROR;
    }

    if (*token_len < user_cmd.token_size) {
        printf("token too small.\n");
        return INSUFFICIENT_BUFFER_LEN;
    }

    read_len = read(ctx->fd, token, user_cmd.token_size);
    if (read_len == EOF || read_len == 0 || read_len != user_cmd.token_size) {
        printf("Failed to read token. errno: %d\n", errno);
        return TSI_ERROR;
    }
    *token_len = read_len;

    return TSI_SUCCESS;
}

int get_dev_cert(tsi_ctx *ctx, unsigned char *dev_cert, size_t *dev_cert_len)
{
    int ret;
    cca_dev_cert_t cca_dev_cert = {0};

    if (ctx == NULL || dev_cert == NULL) {
        return NULL_INPUT;
    }
    ret = ioctl(ctx->fd, TMM_GET_DEV_CERT, &cca_dev_cert);
    if (ret != 0) {
        printf("Failed to get dev cert. errno: %d\n", errno);
        return TSI_ERROR;
    }

    if (cca_dev_cert.size > *dev_cert_len) {
        return INSUFFICIENT_BUFFER_LEN;
    }
    memcpy(dev_cert, cca_dev_cert.value, cca_dev_cert.size);
    *dev_cert_len = cca_dev_cert.size;

    return TSI_SUCCESS;
}
