/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "token_validate.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/limits.h>
#include "utils.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_sign1_verify.h"

static enum t_cose_err_t
init_signing_key(struct t_cose_key *key_pair,
                 struct q_useful_buf_c pub_key)
{

    enum t_cose_err_t ret;
    EVP_PKEY *pkey = NULL;

    pkey = d2i_PUBKEY(NULL, (const unsigned char **)&(pub_key.ptr), pub_key.len);
    if (pkey == NULL) {
        printf("Failed to load pubkey\n");
        ret = T_COSE_ERR_FAIL;
        goto done;
    }

    key_pair->k.key_ptr = pkey;
    key_pair->crypto_lib = T_COSE_CRYPTO_LIB_OPENSSL;
    ret = T_COSE_SUCCESS;

done:
    return ret;
}

static void free_signing_key(struct t_cose_key key_pair)
{
    EVP_PKEY_free(key_pair.k.key_ptr);
}

static bool read_x509_from_pem(const char *prefix, const char *filename, X509 **x509_cert)
{
    char fullpath[PATH_MAX] = {0};
    FILE *pFile = NULL;

    snprintf(fullpath, sizeof(fullpath), "%s/%s", prefix, filename);
    pFile = fopen(fullpath, "re");
    if (!pFile) {
        printf("Cannot open pem file %s", fullpath);
        return false;
    }

    *x509_cert = PEM_read_X509(pFile, NULL, NULL, NULL);
    if (!x509_cert) {
        printf("Failed to read x509 from file: %s\n", fullpath);
        fclose(pFile);
        return false;
    }

    fclose(pFile);
    return true;
}

static bool x509_validate_signature(X509 *child_cert, X509 *intermediate_cert, X509 *parent_cert)
{
    bool ret = false;
    X509_STORE *store = NULL;
    X509_STORE_CTX *store_ctx = NULL;

    /* Create the store */
    store = X509_STORE_new();
    if (!store)
        goto err;

    /* Add the parent cert to the store */
    if (X509_STORE_add_cert(store, parent_cert) != 1) {
        printf("Failed to add parent_cert to x509_store\n");
        goto err;
    }

    /* Add the intermediate cert to the store */
    if (intermediate_cert) {
        if (X509_STORE_add_cert(store, intermediate_cert) != 1) {
            printf("Failed to add intermediate_cert to x509_store\n");
            goto err;
        }
    }

    /* Create the store context */
    store_ctx = X509_STORE_CTX_new();
    if (!store_ctx) {
        printf("Failed to create x509_store_context\n");
        goto err;
    }

    /* Pass the store (parent and intermediate cert) and child cert (need
     * to be verified) into the store context
     */
    if (X509_STORE_CTX_init(store_ctx, store, child_cert, NULL) != 1) {
        printf("Failed to initialize 509_store_context\n");
        goto err;
    }

    /* Specify which cert to verify */
    X509_STORE_CTX_set_cert(store_ctx, child_cert);

    /* Verify the certificate */
    ret = X509_verify_cert(store_ctx);
    if (ret != 1) {
        printf("Failed to verify x509 cert: %s\n",
            X509_verify_cert_error_string(X509_STORE_CTX_get_error(store_ctx)));
        goto err;
    }
    ret = true;

err:
    if (store_ctx) {
        X509_STORE_CTX_free(store_ctx);
    }
    if (store) {
        X509_STORE_free(store);
    }
    return ret;
}

bool validate_aik_cert_chain(X509 *x509_aik, X509 *x509_sub, X509 *x509_root)
{
    bool ret;

    if (x509_aik == NULL || x509_sub == NULL || x509_root == NULL) {
        return false;
    }

    /* Verify the self-signed root-cert */
    ret = x509_validate_signature(x509_root, NULL, x509_root);
    if (!ret) {
        printf("Failed to validate signature of x509_root cert\n");
        return ret;
    }

    /* Verify the sub-cert signed by root-cert */
    ret = x509_validate_signature(x509_sub, NULL, x509_root);
    if (!ret) {
        printf("Failed to validate signature of x509_sub cert\n");
        return ret;
    }

    /* Verify the aik-cert by sub-cert */
    ret = x509_validate_signature(x509_aik, x509_sub, x509_root);
    if (!ret) {
        printf("Failed to validate signature of x509_aik cert\n");
        return ret;
    }

    return ret;
}

bool verify_cvm_pubkey(qbuf_t pub_key, X509 *x509_aik)
{
    bool ret = false;
    EVP_PKEY *pkey1;
    EVP_PKEY *pkey2;

    /* Extract the AIK public key */
    pkey1 = X509_get_pubkey(x509_aik);
    if (!pkey1) {
        printf("Failed to extract pub-key from aik_cert\n");
        goto done;
    }

    pkey2 = d2i_PUBKEY(NULL, (const unsigned char **)&(pub_key.ptr), pub_key.len);
    if (pkey2 == NULL) {
        printf("Failed to load pubkey\n");
        goto done;
    }

    if (!EVP_PKEY_cmp(pkey1, pkey2)) {
        goto done;
    }
    ret = true;

done:
    EVP_PKEY_free(pkey1);
    EVP_PKEY_free(pkey2);
    return ret;
}

bool verify_cvm_cose_sign(qbuf_t signed_cose, qbuf_t pub_key)
{
    qbuf_t payload;
    enum t_cose_err_t ret;
    struct t_cose_key key_pair;
    struct t_cose_sign1_verify_ctx verify_ctx;

    /* Export public key to an ECDSA key pair */
    ret = init_signing_key(&key_pair, pub_key);
    if (ret != T_COSE_SUCCESS) {
        printf("Failed to made EC key with curve secp384r1: %d\n", ret);
        return false;
    }

    t_cose_sign1_verify_init(&verify_ctx, 0);

    t_cose_sign1_set_verification_key(&verify_ctx, key_pair);

    printf("Initialized t_cose for verification and set verification key\n");

    ret = t_cose_sign1_verify(&verify_ctx,
                              signed_cose,  /* COSE to verify */
                              &payload,  /* Payload from signed_cose */
                              NULL);  /* Don't return parameters */
    if (ret != T_COSE_SUCCESS) {
        free_signing_key(key_pair);
        printf("t_cose_sign1_verify ret: %d\n", ret);
        return false;
    }

    free_signing_key(key_pair);
    return true;
}

bool verify_cca_token_signatures(cert_info_t *cert_info,
                                qbuf_t cvm_cose,
                                qbuf_t cvm_pub_key,
                                qbuf_t cvm_pub_key_algo)
{
    X509 *x509_root = X509_new();
    X509 *x509_sub = X509_new();
    X509 *x509_aik = X509_new();
    bool ret;
    unsigned int ret_bits = 0xFFFFFFFF;
    unsigned int index = 0;

    /* Verify cvm signature */
    ret = verify_cvm_cose_sign(cvm_cose, cvm_pub_key);
    printf("Verifying if cVM token signature is signed by RAK: %s \n",
           ret ? "Success" : "Failed");
    if (ret == false) {
        ret_bits &= ~(1 << index);
    }
    index += 1;

    /* Read aik cert file */
    if (!read_x509_from_pem(cert_info->cert_path_prefix,
                            cert_info->aik_cert_filename, &x509_aik)) {
        printf("Failed to read x509_aik cert\n");
        ret = false;
        ret_bits &= ~(1 << index);
    }
    index += 1;

    /* Verify cvm pubkey */
    ret = verify_cvm_pubkey(cvm_pub_key, x509_aik);
    printf("Verifying if cvm pubkey matches aik pubkey: %s \n",
           ret ? "Success" : "Failed");
    if (ret == false) {
        ret_bits &= ~(1 << index);
    }
    index += 1;

    /* Download root cert */
    if (!file_exists(cert_info->cert_path_prefix,
                     cert_info->root_cert_filename)) {
        download_cert_pem(cert_info->cert_path_prefix,
                          cert_info->root_cert_filename,
                          cert_info->root_cert_url);
    }

    if (!read_x509_from_pem(cert_info->cert_path_prefix,
                            cert_info->root_cert_filename, &x509_root)) {
        printf("Failed to read x509_root cert\n");
        ret = false;
        ret_bits &= ~(1 << index);
    }
    index += 1;

    /* Download sub cert */
    if (!file_exists(cert_info->cert_path_prefix,
                     cert_info->sub_cert_filename)) {
        download_cert_pem(cert_info->cert_path_prefix,
                          cert_info->sub_cert_filename,
                          cert_info->sub_cert_url);
    }

    if (!read_x509_from_pem(cert_info->cert_path_prefix,
                            cert_info->sub_cert_filename, &x509_sub)) {
        printf("Failed to read x509_sub cert\n");
        ret = false;
        ret_bits &= ~(1 << index);
    }
    index += 1;

    ret = validate_aik_cert_chain(x509_aik, x509_sub, x509_root);
    printf("Verifying IAK certificate chain: %s \n",
           ret ? "Success" : "Failed");
    if (ret == false) {
        ret_bits &= ~(1 << index);
    }

    X509_free(x509_root);
    X509_free(x509_sub);
    X509_free(x509_aik);

    printf("CCA token singature validate [%s]\n",
           (ret_bits == 0xFFFFFFFF) ? "Success" : "Failed");
    return (ret_bits == 0xFFFFFFFF);
}
