#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "binary_blob.h"
#include "vcca_event_log.h"
#include "vcca_firmware_state.h"
#include "verify.h"

/* Length of REM value read from rem.txt file (each value is 32 bytes, represented as 64 hex characters) */
#define REM_HEX_LENGTH 64
#define HASH_STR_LENGTH 64

/* JSON parsing state */
typedef struct {
    char* grub;
    char* grub_cfg;
    char* kernel;
    char* initramfs;
    char* hash_alg;
} firmware_reference_t;

/* Forward declarations of all static functions */
static bool hex_to_bytes(const char* hex_str, uint8_t* bytes, size_t length);
static void bytes_to_hex_string(const uint8_t* bytes, size_t len, char* hex_str);
static bool parse_json_file(const char* filename, firmware_reference_t* ref);
static void free_firmware_reference(firmware_reference_t* ref);
static bool compare_and_print_hash(const char* component_name, const char* ref_hash,
                                     const uint8_t* actual_hash, size_t hash_size);
static char* extract_json_string(const char* json, const char* key);

static bool hex_to_bytes(const char* hex_str, uint8_t* bytes, size_t length)
{
    if (!hex_str || !bytes || strlen(hex_str) != length * 2) {
        return false;
    }

    for (size_t i = 0; i < length; i++) {
        char hex[3] = {hex_str[i * 2], hex_str[i * 2 + 1], 0};
        unsigned int value;
        if (sscanf(hex, "%02x", &value) != 1) {
            return false;
        }
        bytes[i] = (uint8_t)value;
    }
    return true;
}

bool read_token_rem(rem_t rems[REM_COUNT])
{
    /* Read REM file content */
    size_t file_size;
    char* file_content = read_text_file(g_config.rem_file, &file_size);
    if (!file_content) {
        return false;
    }

    char* line = file_content;
    int rem_index = 0;
    bool success = false;

    /* Process each line */
    while (line && rem_index < REM_COUNT) {
        /* Find end of line */
        char* newline = strchr(line, '\n');
        if (newline) {
            *newline = '\0';
        }

        /* Find REM marker */
        char* pos = strstr(line, "REM[");
        if (pos) {
            /* Find the REM value hex string */
            pos = strchr(line, ':');
            if (pos) {
                pos++; /* Skip colon */

                /* Skip spaces */
                while (*pos == ' ') {
                    pos++;
                }

                /* Convert hex string to byte array */
                if (!hex_to_bytes(pos, rems[rem_index].data, REM_LENGTH_BYTES)) {
                    printf("Error: Failed to parse REM[%d] value\n", rem_index);
                    goto cleanup;
                }

                rem_index++;
            }
        }

        /* Move to next line */
        line = newline ? newline + 1 : NULL;
    }

    success = (rem_index == REM_COUNT);

cleanup:
    free(file_content);
    return success;
}

void verify_single_rem(int rem_index, const rem_t* rem1, const rem_t* rem2)
{
    if (!rem1 || !rem2) {
        printf("Error: Invalid REM pointers for verification\n");
        return;
    }

    if (rem_compare(rem1, rem2)) {
        printf("REM[%d] passed the verification.\n", rem_index);
    } else {
        printf("REM[%d] did not pass the verification\n", rem_index);
        printf("Expected: ");
        rem_dump(rem1);
        printf("Got:      ");
        rem_dump(rem2);
    }
}

bool verify_firmware_state(const char* json_file, const vcca_firmware_log_state_t* state)
{
    if (!json_file || !state) {
        return false;
    }

    firmware_reference_t ref = {0};
    bool result = false;

    /* Parse JSON file */
    if (!parse_json_file(json_file, &ref)) {
        printf("Error: Failed to parse JSON file\n");
        return false;
    }

    /* Verify hash algorithm */
    if (strcmp(ref.hash_alg, "sha-256") != 0) {
        printf("Error: Unsupported hash algorithm: %s\n", ref.hash_alg);
        goto cleanup;
    }

    printf("\nVerifying firmware components...\n");

    /* Verify EFI state (grub) */
    if (state->efi && state->efi->image_count > 0) {
        bool found_match = false;
        for (uint32_t i = 0; i < state->efi->image_count; i++) {
            if (compare_and_print_hash("GRUB", ref.grub,
                state->efi->images[i].image_hash,
                state->efi->images[i].image_hash_size)) {
                found_match = true;
                break;
            }
        }
        if (!found_match) {
            goto cleanup;
        }
    }

    /* Verify GRUB configuration */
    if (state->grub && state->grub->config_hash) {
        if (!compare_and_print_hash("GRUB config", ref.grub_cfg,
            state->grub->config_hash,
            state->grub->config_hash_size)) {
            goto cleanup;
        }
    }

    /* Verify kernel and initramfs */
    if (state->linux_kernel) {
        if (state->linux_kernel->kernel_hash) {
            if (!compare_and_print_hash("Kernel", ref.kernel,
                state->linux_kernel->kernel_hash,
                state->linux_kernel->kernel_hash_size)) {
                goto cleanup;
            }
        }
        if (state->linux_kernel->initrd_hash) {
            if (!compare_and_print_hash("Initramfs", ref.initramfs,
                state->linux_kernel->initrd_hash,
                state->linux_kernel->initrd_hash_size)) {
                goto cleanup;
            }
        }
    }

    printf("\nAll firmware components verification passed\n");
    result = true;

cleanup:
    free_firmware_reference(&ref);
    return result;
}

bool verify_rem(void)
{
    printf("=> Verify REM\n");
    /* 1. Read CCEL file */
    size_t file_size;
    uint8_t* ccel_data = read_file_data(g_config.ccel_file, &file_size);
    if (!ccel_data) {
        return false;
    }

    /* 2. Get the start address and length of event log area from CCEL */
    /* The processing is simplified here. The CCEL structure should be parsed. */
    size_t log_area_start = 0;  /* Actually read from CCEL */
    size_t log_area_length = 0;

    /* 3. Initialize event log processor */
    vcca_event_log_t event_log;
    if (!vcca_event_log_init(&event_log, log_area_start, log_area_length)) {
        free(ccel_data);
        return false;
    }

    /* 4. Replay event log to calculate REM values */
    if (!vcca_event_log_replay(&event_log)) {
        free(ccel_data);
        return false;
    }

    /* 5. Read REM values from attestation token */
    rem_t token_rems[REM_COUNT];
    if (!read_token_rem(token_rems)) {
        printf("Error: Could not read REM file: %s\n", g_config.rem_file);
        free(ccel_data);
        return false;
    }

    /* 6. Verify each REM value */
    printf("\nVerifying REM values...\n");
    bool all_rems_passed = true;
    for (int i = 0; i < REM_COUNT; i++) {
        verify_single_rem(i, &token_rems[i], &event_log.rems[i]);
        if (!rem_compare(&token_rems[i], &event_log.rems[i])) {
            all_rems_passed = false;
        }
    }

    if (!all_rems_passed) {
        printf("\nREM verification failed, skipping firmware state verification\n");
        free(ccel_data);
        return false;
    }

    printf("\nAll REM values verified successfully\n");

    /* 7. If JSON file is provided and REM verification passed, verify firmware state */
    bool final_result = true;
    if (g_config.json_file) {
        printf("\nVerifying firmware state...\n");
        vcca_firmware_log_state_t* state = vcca_firmware_log_state_create(&event_log);
        if (!state) {
            printf("Error: Failed to create firmware state\n");
            free(ccel_data);
            return false;
        }

        if (!vcca_firmware_log_state_extract(&event_log, state)) {
            printf("Error: Failed to extract firmware state\n");
            vcca_firmware_log_state_free(state);
            free(ccel_data);
            return false;
        }

        if (!verify_firmware_state(g_config.json_file, state)) {
            printf("Error: Firmware state verification failed\n");
            vcca_firmware_log_state_free(state);
            free(ccel_data);
            final_result = false;
        }

        vcca_firmware_log_state_free(state);
    }

    free(ccel_data);
    return final_result;
}

/* Helper function: Convert byte array to hex string */
static void bytes_to_hex_string(const uint8_t* bytes, size_t len, char* hex_str)
{
    for (size_t i = 0; i < len; i++) {
        sprintf(hex_str + (i * 2), "%02x", bytes[i]);
    }
}

/* Helper function: Extract string value from JSON */
static char* extract_json_string(const char* json, const char* key)
{
    char* value = NULL;
    char search_key[64];
    snprintf(search_key, sizeof(search_key), "\"%s\":", key);
    
    char* pos = strstr(json, search_key);
    if (pos) {
        pos = strchr(pos + strlen(search_key), '"');
        if (pos) {
            pos++; /* Skip quote */
            char* end = strchr(pos, '"');
            if (end) {
                size_t len = end - pos;
                value = (char*)malloc(len + 1);
                if (value) {
                    strncpy(value, pos, len);
                    value[len] = '\0';
                }
            }
        }
    }
    return value;
}

/* Helper function: Parse JSON file */
static bool parse_json_file(const char* filename, firmware_reference_t* ref)
{
    if (!filename || !ref) {
        return false;
    }

    size_t file_size;
    char* json_content = read_text_file(filename, &file_size);
    if (!json_content) {
        return false;
    }

    ref->grub = extract_json_string(json_content, "grub");
    ref->grub_cfg = extract_json_string(json_content, "grub.cfg");
    ref->kernel = extract_json_string(json_content, "kernel");
    ref->initramfs = extract_json_string(json_content, "initramfs");
    ref->hash_alg = extract_json_string(json_content, "hash_alg");

    free(json_content);
    return (ref->grub && ref->grub_cfg && ref->kernel && ref->initramfs && ref->hash_alg);
}

/* Helper function: Free JSON parsing results */
static void free_firmware_reference(firmware_reference_t* ref)
{
    if (!ref) {
        return;
    }
    free(ref->grub);
    free(ref->grub_cfg);
    free(ref->kernel);
    free(ref->initramfs);
    free(ref->hash_alg);
}

/* Helper function: Compare hash value and print result */
static bool compare_and_print_hash(const char* component_name, const char* ref_hash,
                                      const uint8_t* actual_hash, size_t hash_size)
{
    if (!ref_hash || !actual_hash) {
        return false;
    }
    
    char actual_hex[HASH_STR_LENGTH + 1] = {0};
    bytes_to_hex_string(actual_hash, hash_size, actual_hex);
    
    bool match = (strncmp(ref_hash, actual_hex, HASH_STR_LENGTH) == 0);
    printf("\n%s verification %s\n", component_name, match ? "passed" : "failed");
    printf("Expected: %s\n", ref_hash);
    printf("Got:      %s\n", actual_hex);
    return match;
}