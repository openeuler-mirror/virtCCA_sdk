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

#ifndef VIRTCCA_SEALING_KEY_H
#define VIRTCCA_SEALING_KEY_H

#include <stdint.h>

#define SEALING_KEY_LEN 32
#define SEALING_USER_PARAM_LEN 64

typedef enum {
    SEALING_HMAC_SHA256
} SEALING_KEY_ALG;

/**
 * @brief   Get a sealing key from TMM with specified derivation parameters by PBKDF2 HUK derived
 *
 * @param   alg             [IN]  The HMAC algorithm used in derive sealing key
 * @param   user_param      [IN]  A user param used in huk derivation, length should be 64 byte.
 *                                This param is optional, set it to NULL to derived without user param.
 * @param   user_param_len  [IN]  Length of the user param in byte, should be 64, or set to 0
 *                                when not specifying user param.
 * @param   sealing_key     [OUT] Addr of the derived sealing key
 * @param   key_len         [IN]  Length of the sealing_key buff, should not less than 32
 *
 * @return  0: successfully get the derived key
 *          -1: failed
*/
int get_sealing_key(SEALING_KEY_ALG alg, uint8_t* user_param, uint32_t user_param_len, uint8_t* sealing_key,
                    uint32_t key_len);

#endif