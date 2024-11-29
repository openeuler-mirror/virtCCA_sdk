/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * virtCCA_sdk is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "sealing_key.h"

#define SEALING_KEY_DEV_NAME "/dev/sealingkey"

struct sealing_key_params {
    uint32_t alg;
    uint8_t user_param[SEALING_USER_PARAM_LEN];
    uint32_t user_param_len;
    uint8_t sealing_key[SEALING_KEY_LEN];
};

#define SEAL_KEY_IOC_MAGIC 'd'
#define IOCTL_SEALING_KEY _IOWR(SEAL_KEY_IOC_MAGIC, 0, struct sealing_key_params)

int get_sealing_key(SEALING_KEY_ALG alg, uint8_t* user_param, uint32_t user_param_len, uint8_t* sealing_key,
                    uint32_t key_len)
{
    int rc = 0;
    int fd = -1;
    struct sealing_key_params args = { 0 };

    if (user_param && user_param_len != SEALING_USER_PARAM_LEN) {
        printf("invalid salt len %d, should be equal %d\n", user_param_len, SEALING_USER_PARAM_LEN);
        return -1;
    }

    if (key_len < SEALING_KEY_LEN) {
        printf("invalid sealing key len %d, should not less than %d\n", key_len, SEALING_KEY_LEN);
        return -1;
    }

    switch (alg) {
        case SEALING_HMAC_SHA256:
            break;
        default:
            printf("current version not support this mode, alg: %d\n", alg);
            return -1;
    }

    args.alg = alg;
    if (user_param) {
        (void)memcpy(args.user_param, user_param, user_param_len);
        args.user_param_len = user_param_len;
    }

    fd = open(SEALING_KEY_DEV_NAME, O_RDWR);
    if (fd < 0) {
        printf("open dev %s failed, err: %s\n", SEALING_KEY_DEV_NAME, strerror(errno));
        return -1;
    }

    rc = ioctl(fd, IOCTL_SEALING_KEY, &args);
    if (rc) {
        if (errno) {
            printf("ioctl failed, err: %s\n", strerror(errno));
        } else {
            printf("driver got sealing key failed\n");
        }
        (void)close(fd);
        return -1;
    }

    (void)memcpy(sealing_key, args.sealing_key, SEALING_KEY_LEN);
    (void)close(fd);
    return 0;
}