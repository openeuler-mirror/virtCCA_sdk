#ifndef VCCA_FIRMWARE_STATE_H
#define VCCA_FIRMWARE_STATE_H

#include <stdint.h>
#include <stdbool.h>
#include "vcca_event_log.h"

/* EFI state structure */
typedef struct {
    uint8_t* image_hash;
    uint32_t image_hash_size;
    char* image_path;
} vcca_efi_image_t;

typedef struct {
    vcca_efi_image_t* images;
    uint32_t image_count;
} vcca_efi_state_t;

/* GRUB conf state structure */
typedef struct {
    uint8_t* config_hash;
    uint32_t config_hash_size;
} vcca_grub_state_t;

/* Linux kernel state structure */
typedef struct {
    uint8_t* kernel_hash;
    uint32_t kernel_hash_size;
    uint8_t* initrd_hash;
    uint32_t initrd_hash_size;
} vcca_linux_kernel_state_t;

/* Firmware log state structure */
typedef struct {
    vcca_efi_state_t* efi;
    vcca_grub_state_t* grub;
    vcca_linux_kernel_state_t* linux_kernel;
    vcca_event_log_entry_t* raw_events;
    uint32_t raw_events_count;
    uint16_t hash_algo;
} vcca_firmware_log_state_t;

/* Function declarations */
vcca_firmware_log_state_t* vcca_firmware_log_state_create(vcca_event_log_t* log);
void vcca_firmware_log_state_free(vcca_firmware_log_state_t* state);
bool vcca_firmware_log_state_extract(vcca_event_log_t* log, vcca_firmware_log_state_t* state);
void vcca_firmware_log_state_print(const vcca_firmware_log_state_t* state);

#endif /* VCCA_FIRMWARE_STATE_H */