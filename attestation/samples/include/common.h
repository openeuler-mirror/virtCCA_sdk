#ifndef COMMON_H
#define COMMON_H

#define CHALLENGE_SIZE (64U)
#define MAX 4096
#define PORT 7220
#define VERIFY_SUCCESS 0
#define VERIFY_FAILED 1

enum MSG_ID {
    DEVICE_CERT_MSG_ID = 0x1001,
    ATTEST_MSG_ID,
    VERIFY_SUCCESS_MSG_ID,
    VERIFY_FAILED_MSG_ID
};

#endif /* COMMON_H */
