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
#include "huk_derive.h"

#define HUK_DERIVE_KEY_DEV_NAME "/dev/tsi_huk"

struct huk_derive_params {
    uint8_t salt[SEALING_SALT_LEN];
    uint32_t salt_len;
    uint8_t sealing_key[SEALING_KEY_LEN];
};

#define HUK_IOC_MAGIC 'd'
#define HUK_IOCTL_DERIVE_KEY _IOWR(HUK_IOC_MAGIC, 0, struct huk_derive_params)

int get_sealing_key(uint8_t* salt, uint32_t salt_len, uint8_t* sealing_key)
{
    int rc = 0;
    int fd = -1;
    struct huk_derive_params args = { 0 };

    if (salt && salt_len != SEALING_SALT_LEN) {
        printf("ERROR: invalid salt len: %d! len should be within 64\n", salt_len);
        return -1;
    }

    if (salt) {
        (void)memcpy(args.salt, salt, salt_len);
        args.salt_len = salt_len;
    }

    fd = open(HUK_DERIVE_KEY_DEV_NAME, O_RDWR);
    if (fd < 0) {
        printf("open dev %s failed, err: %s\n", HUK_DERIVE_KEY_DEV_NAME, strerror(errno));
        return -1;
    }

    rc = ioctl(fd, HUK_IOCTL_DERIVE_KEY, &args);
    if (rc < 0) {
        printf("ioctl failed, err: %s,\n", strerror(errno));
        (void)close(fd);
        return -1;
    }

    (void)memcpy(sealing_key, args.sealing_key, SEALING_KEY_LEN);
    (void)close(fd);
    return 0;
}