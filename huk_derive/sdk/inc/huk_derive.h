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

#ifndef VIRTCCA_HUK_DERIVE_KEY_H
#define VIRTCCA_HUK_DERIVE_KEY_H

#include <stdint.h>

#define SEALING_KEY_LEN 32
#define SEALING_SALT_LEN 64

/**
 * @brief   Get a sealing key from TMM with specified derivation parameters by PBKDF2 HUK derived
 *
 * @param   salt        [IN]  A user param used in huk derivation, length should be 64 byte.
 *                            This param is optional, set it to NULL to derived without user param.
 * @param   salt_len    [IN]  Length of the user param in byte, should be 64. or set to 0 when not specifying user param.
 * @param   sealing_key [OUT] Addr of the output derived key, make sure that enough memory(>=32) had been allocated to the address.
 *
 * @return  0: successfully get the derived key
 *          -1: failed
*/
int get_sealing_key(uint8_t* salt, uint32_t salt_len, uint8_t* sealing_key);

#endif