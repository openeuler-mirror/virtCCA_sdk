#ifndef COMMON_H
#define COMMON_H

#define CHALLENGE_SIZE (64U)
#define MAX_MEASUREMENT_SIZE 64
#define MAX_MEASUREMENT_HEX_SIZE (MAX_MEASUREMENT_SIZE * 2)
#define MAX 4096
#define PORT 7220
#define VERIFY_SUCCESS 0
#define VERIFY_FAILED 1
#define VERIFY_CONTINUE 2

enum MSG_ID {
    DEVICE_CERT_MSG_ID = 0x1001,
    ATTEST_MSG_ID,
    VERIFY_SUCCESS_MSG_ID,
    VERIFY_FAILED_MSG_ID
};

typedef struct {
    uint32_t ip;
    uint16_t port;
    uint8_t measurement[MAX_MEASUREMENT_SIZE];
    uint32_t meas_len;
    uint8_t challenge[CHALLENGE_SIZE];
} client_args;

typedef struct {
    uint32_t ip;
    uint16_t port;
} server_args;

#endif /* COMMON_H */
