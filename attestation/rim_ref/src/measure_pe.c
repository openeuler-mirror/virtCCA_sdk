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
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

/* Enumeration of EFI_STATUS */
#define EFI_SUCCESS 0
#define EFI_UNSUPPORTED 2
#define EFI_OUT_OF_RESOURCES 9

#define EFI_ERROR(x) ((x) != EFI_SUCCESS)

typedef size_t uintn_t;

/* Define macros to build data structure signatures from characters. */
#define SIGNATURE_16(A, B) (((A) | ((B) << 8)))
#define SIGNATURE_32(A, B, C, D) (SIGNATURE_16(A, B) | (SIGNATURE_16(C, D) << 16))

#define SHA256_DIGEST_SIZE 32
#define MIN_ARGC 2

/* EXE file formats */
#define EFI_IMAGE_DOS_SIGNATURE SIGNATURE_16('M', 'Z')
#define EFI_IMAGE_NT_SIGNATURE SIGNATURE_32('P', 'E', '\0', '\0')

#define EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10b
#define EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES 16
#define EFI_IMAGE_DIRECTORY_ENTRY_SECURITY 4

/* Header Data Directories. */
typedef struct {
    uint32_t virtual_address;
    uint32_t size;
} efi_image_data_directory;

/*
 * PE images can start with an optional DOS header, so if an image is run
 * under DOS it can print an error message.
 */
typedef struct {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
} efi_image_dos_header;

/* COFF File Header (Object and Image). */
typedef struct {
    uint16_t machine;
    uint16_t number_of_sections;
    uint32_t time_date_stamp;
    uint32_t pointer_to_symbol_table;
    uint32_t number_of_symbols;
    uint16_t size_of_optional_header;
    uint16_t characteristics;
} efi_image_file_header;

/* Optional Header Standard Fields for PE32. */
typedef struct {
    /* Standard fields */
    uint16_t magic;
    uint8_t major_linker_version;
    uint8_t minor_linker_version;
    uint32_t size_of_code;
    uint32_t size_of_initialized_data;
    uint32_t size_of_uninitialized_data;
    uint32_t address_of_entry_point;
    uint32_t base_of_code;
    uint32_t base_of_data;

    /* Optional Header Windows-Specific Fields. */
    uint32_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t major_operating_system_version;
    uint16_t minor_operating_system_version;
    uint16_t major_image_version;
    uint16_t minor_image_version;
    uint16_t major_subsystem_version;
    uint16_t minor_subsystem_version;
    uint32_t win32_version_value;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t checksum;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint32_t size_of_stack_reserve;
    uint32_t size_of_stack_commit;
    uint32_t size_of_heap_reserve;
    uint32_t size_of_heap_commit;
    uint32_t loader_flags;
    uint32_t number_of_rva_and_sizes;
    efi_image_data_directory data_directory[EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES];
} efi_image_optional_header32;

/* Optional Header Standard Fields for PE32+. */
typedef struct {
    /* Standard fields */
    uint16_t magic;
    uint8_t major_linker_version;
    uint8_t minor_linker_version;
    uint32_t size_of_code;
    uint32_t size_of_initialized_data;
    uint32_t size_of_uninitialized_data;
    uint32_t address_of_entry_point;
    uint32_t base_of_code;

    /* Optional Header Windows-Specific Fields. */
    uint64_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t major_operating_system_version;
    uint16_t minor_operating_system_version;
    uint16_t major_image_version;
    uint16_t minor_image_version;
    uint16_t major_subsystem_version;
    uint16_t minor_subsystem_version;
    uint32_t win32_version_value;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t checksum;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint64_t size_of_stack_reserve;
    uint64_t size_of_stack_commit;
    uint64_t size_of_heap_reserve;
    uint64_t size_of_heap_commit;
    uint32_t loader_flags;
    uint32_t number_of_rva_and_sizes;
    efi_image_data_directory data_directory[EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES];
} efi_image_optional_header64;

typedef struct {
    uint32_t signature;
    efi_image_file_header file_header;
    efi_image_optional_header32 optional_header;
} efi_image_nt_headers32;

typedef struct {
    uint32_t signature;
    efi_image_file_header file_header;
    efi_image_optional_header64 optional_header;
} efi_image_nt_headers64;

#define EFI_IMAGE_SIZEOF_SHORT_NAME 8

/* Section Table. This table immediately follows the optional header. */
typedef struct {
    uint8_t name[EFI_IMAGE_SIZEOF_SHORT_NAME];
    union {
        uint32_t physical_address;
        uint32_t virtual_size;
    } misc;
    uint32_t virtual_address;
    uint32_t size_of_raw_data;
    uint32_t pointer_to_raw_data;
    uint32_t pointer_to_relocations;
    uint32_t pointer_to_linenumbers;
    uint16_t number_of_relocations;
    uint16_t number_of_linenumbers;
    uint32_t characteristics;
} efi_image_section_header;


/* Union of PE32, PE32+ headers. */
typedef union {
    efi_image_nt_headers32 pe32;
    efi_image_nt_headers64 pe32plus;
} efi_image_optional_header_union;

typedef union {
    efi_image_nt_headers32 *pe32;
    efi_image_nt_headers64 *pe32plus;
    efi_image_optional_header_union *union_hdr;
} efi_image_optional_header_ptr_union;

typedef struct {
    unsigned char sha256[32];
} tpml_digest_values_t;

typedef struct {
    EVP_MD_CTX *md_ctx;
} my_hash_context_t;

typedef my_hash_context_t *hash_handle_t;

/* Start hash sequence. */
static uint64_t hash_start(hash_handle_t *hash_handle_out)
{
    if (hash_handle_out == NULL) {
        return EFI_UNSUPPORTED;
    }

    my_hash_context_t *context = (my_hash_context_t *)malloc(sizeof(my_hash_context_t));
    if (context == NULL) {
        return EFI_OUT_OF_RESOURCES;
    }

    context->md_ctx = EVP_MD_CTX_new();
    if (!context->md_ctx) {
        free(context);
        return EFI_OUT_OF_RESOURCES;
    }

    if (!EVP_DigestInit_ex(context->md_ctx, EVP_sha256(), NULL)) {
        EVP_MD_CTX_free(context->md_ctx);
        free(context);
        return EFI_UNSUPPORTED;
    }

    *hash_handle_out = context;
    return EFI_SUCCESS;
}

/* Update hash sequence data. */
static uint64_t hash_update(hash_handle_t hash_handle, const uint8_t *data, size_t data_size)
{
    if (hash_handle == NULL || data == NULL) {
        return EFI_UNSUPPORTED;
    }

    if (!EVP_DigestUpdate(hash_handle->md_ctx, data, data_size)) {
        return EFI_UNSUPPORTED;
    }

    return EFI_SUCCESS;
}

/* Hash sequence complete and extend to PCR. */
static uint64_t hash_complete_and_extend(hash_handle_t hash_handle, const uint8_t *event_data, size_t event_size,
                                         tpml_digest_values_t *digest_list)
{
    if (hash_handle == NULL || digest_list == NULL) {
        return EFI_UNSUPPORTED;
    }

    unsigned char final_digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;

    if (!EVP_DigestFinal_ex(hash_handle->md_ctx, final_digest, &digest_len)) {
        EVP_MD_CTX_free(hash_handle->md_ctx);
        free(hash_handle);
        return EFI_UNSUPPORTED;
    }

    if (digest_len != SHA256_DIGEST_LENGTH) {
        EVP_MD_CTX_free(hash_handle->md_ctx);
        free(hash_handle);
        return EFI_UNSUPPORTED;
    }

    memcpy(digest_list->sha256, final_digest, SHA256_DIGEST_LENGTH);

    EVP_MD_CTX_free(hash_handle->md_ctx);
    free(hash_handle);

    return EFI_SUCCESS;
}

static uint64_t MeasurePeImageAndExtend(uint32_t RtmrIndex, uint64_t ImageAddress, UINTN ImageSize,
    TPML_DIGEST_VALUES *DigestList)
{
    uint64_t Status;
    EFI_IMAGE_DOS_HEADER *DosHdr;
    uint32_t PeCoffHeaderOffset;
    EFI_IMAGE_SECTION_HEADER *Section = NULL;
    uint8_t *HashBase;
    UINTN HashSize;
    UINTN SumOfBytesHashed;
    EFI_IMAGE_SECTION_HEADER *SectionHeader;
    UINTN Index;
    UINTN Pos;
    EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION Hdr;
    uint32_t NumberOfRvaAndSizes;
    uint32_t CertSize;
    HASH_HANDLE HashHandle = NULL;

    Status = EFI_UNSUPPORTED;
    SectionHeader = NULL;

    DosHdr = (EFI_IMAGE_DOS_HEADER *)(uintptr_t)ImageAddress;
    PeCoffHeaderOffset = 0;
    if (DosHdr->e_magic == EFI_IMAGE_DOS_SIGNATURE) {
        PeCoffHeaderOffset = DosHdr->e_lfanew;
    }

    Hdr.Pe32 = (EFI_IMAGE_NT_HEADERS32 *)((uint8_t *)(uintptr_t)ImageAddress + PeCoffHeaderOffset);
    if (Hdr.Pe32->Signature != EFI_IMAGE_NT_SIGNATURE) {
        Status = EFI_UNSUPPORTED;
        goto Finish;
    }

    Status = HashStart(&HashHandle);
    if (EFI_ERROR(Status)) {
        goto Finish;
    }

    if (Hdr.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        NumberOfRvaAndSizes = Hdr.Pe32->OptionalHeader.NumberOfRvaAndSizes;
        HashBase = (uint8_t *)(uintptr_t)ImageAddress;
        HashSize = (uintptr_t)(&Hdr.Pe32->OptionalHeader.CheckSum) - (uintptr_t)HashBase;
    } else {
        NumberOfRvaAndSizes = Hdr.Pe32Plus->OptionalHeader.NumberOfRvaAndSizes;
        HashBase = (uint8_t *)(uintptr_t)ImageAddress;
        HashSize = (uintptr_t)(&Hdr.Pe32Plus->OptionalHeader.CheckSum) - (uintptr_t)HashBase;
    }

    Status = HashUpdate(HashHandle, HashBase, HashSize);
    if (EFI_ERROR(Status)) {
        goto Finish;
    }

    /* skip checksum */
    if (NumberOfRvaAndSizes <= EFI_IMAGE_DIRECTORY_ENTRY_SECURITY) {
        if (Hdr.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            HashBase = (uint8_t *)&Hdr.Pe32->OptionalHeader.CheckSum + sizeof(uint32_t);
            HashSize = Hdr.Pe32->OptionalHeader.SizeOfHeaders - (UINTN)(HashBase - (uint8_t *)(uintptr_t)ImageAddress);
        } else {
            HashBase = (uint8_t *)&Hdr.Pe32Plus->OptionalHeader.CheckSum + sizeof(uint32_t);
            HashSize =
                Hdr.Pe32Plus->OptionalHeader.SizeOfHeaders - (UINTN)(HashBase - (uint8_t *)(uintptr_t)ImageAddress);
        }
        if (HashSize != 0) {
            Status = HashUpdate(HashHandle, HashBase, HashSize);
            if (EFI_ERROR(Status)) {
                goto Finish;
            }
        }
    } else {
        if (Hdr.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            HashBase = (uint8_t *)&Hdr.Pe32->OptionalHeader.CheckSum + sizeof(uint32_t);
            HashSize =
                (UINTN)(&Hdr.Pe32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY]) - (UINTN)HashBase;
        } else {
            HashBase = (uint8_t *)&Hdr.Pe32Plus->OptionalHeader.CheckSum + sizeof(uint32_t);
            HashSize = (UINTN)(&Hdr.Pe32Plus->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY]) -
                (UINTN)HashBase;
        }
        if (HashSize != 0) {
            Status = HashUpdate(HashHandle, HashBase, HashSize);
            if (EFI_ERROR(Status)) {
                goto Finish;
            }
        }
        /* skip the Security Directory */
        if (Hdr.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            HashBase = (uint8_t *)&Hdr.Pe32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY + 1];
            HashSize = Hdr.Pe32->OptionalHeader.SizeOfHeaders - (UINTN)(HashBase - (uint8_t *)(uintptr_t)ImageAddress);
        } else {
            HashBase = (uint8_t *)&Hdr.Pe32Plus->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY + 1];
            HashSize =
                Hdr.Pe32Plus->OptionalHeader.SizeOfHeaders - (UINTN)(HashBase - (uint8_t *)(uintptr_t)ImageAddress);
        }
        if (HashSize != 0) {
            Status = HashUpdate(HashHandle, HashBase, HashSize);
            if (EFI_ERROR(Status)) {
                goto Finish;
            }
        }
    }

    if (Hdr.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        SumOfBytesHashed = Hdr.Pe32->OptionalHeader.SizeOfHeaders;
    } else {
        SumOfBytesHashed = Hdr.Pe32Plus->OptionalHeader.SizeOfHeaders;
    }

    /* order the section header */
    SectionHeader =
        (EFI_IMAGE_SECTION_HEADER *)calloc(Hdr.Pe32->FileHeader.NumberOfSections, sizeof(EFI_IMAGE_SECTION_HEADER));
    if (SectionHeader == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
        goto Finish;
    }

    EFI_IMAGE_SECTION_HEADER *SectionTmp = (EFI_IMAGE_SECTION_HEADER *)((uint8_t *)(uintptr_t)ImageAddress +
        PeCoffHeaderOffset + sizeof(uint32_t) +
        sizeof(EFI_IMAGE_FILE_HEADER) + Hdr.Pe32->FileHeader.SizeOfOptionalHeader);

    for (Index = 0; Index < Hdr.Pe32->FileHeader.NumberOfSections; Index++) {
        memcpy(&SectionHeader[Index], &SectionTmp[Index], sizeof(EFI_IMAGE_SECTION_HEADER));
    }
    for (Index = 1; Index < Hdr.Pe32->FileHeader.NumberOfSections; Index++) {
        EFI_IMAGE_SECTION_HEADER temp;
        memcpy(&temp, &SectionHeader[Index], sizeof(EFI_IMAGE_SECTION_HEADER));
        Pos = Index;
        while (Pos > 0 && (SectionHeader[Pos - 1].PointerToRawData > temp.PointerToRawData)) {
            memcpy(&SectionHeader[Pos], &SectionHeader[Pos - 1], sizeof(EFI_IMAGE_SECTION_HEADER));
            Pos--;
        }
        if (Pos != Index) {
            memcpy(&SectionHeader[Pos], &temp, sizeof(EFI_IMAGE_SECTION_HEADER));
        }
    }

    for (Index = 0; Index < Hdr.Pe32->FileHeader.NumberOfSections; Index++) {
        Section = &SectionHeader[Index];
        if (Section->SizeOfRawData == 0) {
            continue;
        }
        HashBase = (uint8_t *)(uintptr_t)ImageAddress + Section->PointerToRawData;
        HashSize = Section->SizeOfRawData;

        Status = HashUpdate(HashHandle, HashBase, HashSize);
        if (EFI_ERROR(Status)) {
            goto Finish;
        }
        SumOfBytesHashed += HashSize;
    }
 
    if (ImageSize > SumOfBytesHashed) {
        HashBase = (uint8_t *)(uintptr_t)ImageAddress + SumOfBytesHashed;

        if (NumberOfRvaAndSizes <= EFI_IMAGE_DIRECTORY_ENTRY_SECURITY) {
            CertSize = 0;
        } else {
            if (Hdr.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
                CertSize = Hdr.Pe32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
            } else {
                CertSize = Hdr.Pe32Plus->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
            }
        }

        if (ImageSize > (CertSize + SumOfBytesHashed)) {
            HashSize = ImageSize - CertSize - SumOfBytesHashed;
            Status = HashUpdate(HashHandle, HashBase, HashSize);
            if (EFI_ERROR(Status)) {
                goto Finish;
            }
        } else if (ImageSize < (CertSize + SumOfBytesHashed)) {
            Status = EFI_UNSUPPORTED;
            goto Finish;
        }
    }

    Status = HashCompleteAndExtend(HashHandle, RtmrIndex, NULL, 0, DigestList);
    HashHandle = NULL;
    if (EFI_ERROR(Status)) {
        goto Finish;
    }

Finish:
    if (SectionHeader != NULL) {
        free(SectionHeader);
        SectionHeader = NULL;
    }

    if (HashHandle != NULL) {
        free(HashHandle);
        HashHandle = NULL;
    }
    return Status;
}

/**
 * main()  MeasurePeImageAndExtend()
 *  ./MeasurePe <PE>
 */
int main(int argc, char *argv[])
{
    if (argc < MIN_ARGC) {
        printf("Usage: %s <PE_File>\n", argv[0]);
        return -1;
    }

    const char *filename = argv[1];
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("fopen");
        return -1;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }

    long filesize = ftell(fp);
    if (filesize <= 0) {
        fclose(fp);
        printf("File size invalid.\n");
        return -1;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }

    uint8_t *buffer = (uint8_t *)malloc(filesize);
    if (buffer == NULL) {
        fclose(fp);
        printf("Out of memory.\n");
        return -1;
    }

    if (fread(buffer, 1, filesize, fp) != (size_t)filesize) {
        fclose(fp);
        free(buffer);
        printf("Read file error.\n");
        return -1;
    }
    if (fclose(fp) != 0) {
        free(buffer);
        return -1;
    }
    TPML_DIGEST_VALUES digestList = {0};
    uint64_t status = MeasurePeImageAndExtend(0,
        (uint64_t)(uintptr_t)buffer, (UINTN)filesize, &digestList);
    if (status == EFI_SUCCESS) {
        printf("Measure PE image succeed, SHA-256 = ");
        for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
            printf("%02x", digestList.Sha256[i]);
        }
        printf("\n");
    } else {
        printf("Measure PE image failed, uint64_t = %llu\n", (unsigned long long)status);
        return -1;
    }

    free(buffer);
    return 0;
}
