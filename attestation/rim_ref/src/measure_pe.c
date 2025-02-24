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
#include <string.h>
#include <openssl/sha.h>

/* EFI_STATUS */
#define EFI_SUCCESS 0
#define EFI_UNSUPPORTED 2
#define EFI_OUT_OF_RESOURCES 9

/* EFI_ERROR */
#define EFI_ERROR(x) ((x) != EFI_SUCCESS)

typedef size_t UINTN;

#define SIGNATURE_16(A, B) (((A) | ((B) << 8)))
#define SIGNATURE_32(A, B, C, D) (SIGNATURE_16(A, B) | (SIGNATURE_16(C, D) << 16))

#define SHA256_DIGEST_SIZE 32
#define MIN_ARGC 2

#define EFI_IMAGE_DOS_SIGNATURE SIGNATURE_16('M', 'Z')
#define EFI_IMAGE_NT_SIGNATURE SIGNATURE_32('P', 'E', '\0', '\0')

#define EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10b
#define EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES 16
#define EFI_IMAGE_DIRECTORY_ENTRY_SECURITY 4

typedef struct {
    uint32_t VirtualAddress;
    uint32_t Size;
} EFI_IMAGE_DATA_DIRECTORY;

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
} EFI_IMAGE_DOS_HEADER;

typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} EFI_IMAGE_FILE_HEADER;

typedef struct {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;

    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    EFI_IMAGE_DATA_DIRECTORY DataDirectory[EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES];
} EFI_IMAGE_OPTIONAL_HEADER32;

typedef struct {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;

    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    EFI_IMAGE_DATA_DIRECTORY DataDirectory[EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES];
} EFI_IMAGE_OPTIONAL_HEADER64;

typedef struct {
    uint32_t Signature;
    EFI_IMAGE_FILE_HEADER FileHeader;
    EFI_IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} EFI_IMAGE_NT_HEADERS32;

typedef struct {
    uint32_t Signature;
    EFI_IMAGE_FILE_HEADER FileHeader;
    EFI_IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} EFI_IMAGE_NT_HEADERS64;

#define EFI_IMAGE_SIZEOF_SHORT_NAME 8
typedef struct {
    uint8_t Name[EFI_IMAGE_SIZEOF_SHORT_NAME];
    union {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    } Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} EFI_IMAGE_SECTION_HEADER;

typedef struct {
    uint16_t Signature;
    uint16_t Machine;
    uint8_t NumberOfSections;
    uint8_t Subsystem;
    uint16_t StrippedSize;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    EFI_IMAGE_DATA_DIRECTORY DataDirectory[2];
} EFI_TE_IMAGE_HEADER;

typedef union {
    EFI_IMAGE_NT_HEADERS32 Pe32;
    EFI_IMAGE_NT_HEADERS64 Pe32Plus;
    EFI_TE_IMAGE_HEADER Te;
} EFI_IMAGE_OPTIONAL_HEADER_UNION;

typedef union {
    EFI_IMAGE_NT_HEADERS32 *Pe32;
    EFI_IMAGE_NT_HEADERS64 *Pe32Plus;
    EFI_TE_IMAGE_HEADER *Te;
    EFI_IMAGE_OPTIONAL_HEADER_UNION *Union;
} EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION;

typedef struct {
    unsigned char Sha256[32];
} TPML_DIGEST_VALUES;

typedef struct {
    SHA256_CTX Sha256Ctx;
} MY_HASH_CONTEXT;

typedef MY_HASH_CONTEXT *HASH_HANDLE;

static uint64_t HashStart(HASH_HANDLE *HashHandleOut)
{
    if (HashHandleOut == NULL) {
        return EFI_UNSUPPORTED;
    }
    MY_HASH_CONTEXT *Context = (MY_HASH_CONTEXT *)malloc(sizeof(MY_HASH_CONTEXT));
    if (Context == NULL) {
        return EFI_OUT_OF_RESOURCES;
    }
    SHA256_Init(&Context->Sha256Ctx);
    *HashHandleOut = Context;
    return EFI_SUCCESS;
}

static uint64_t HashUpdate(HASH_HANDLE HashHandle, const uint8_t *Data, size_t DataSize)
{
    if (HashHandle == NULL || Data == NULL) {
        return EFI_UNSUPPORTED;
    }
    SHA256_Update(&HashHandle->Sha256Ctx, Data, DataSize);
    return EFI_SUCCESS;
}

static uint64_t HashCompleteAndExtend(HASH_HANDLE HashHandle,
    uint32_t RtmrIndex,
    const uint8_t *EventData,
    size_t EventSize, TPML_DIGEST_VALUES *DigestList)
{
    if (HashHandle == NULL || DigestList == NULL) {
        return EFI_UNSUPPORTED;
    }
    unsigned char FinalDigest[SHA256_DIGEST_SIZE];
    SHA256_Final(FinalDigest, &HashHandle->Sha256Ctx);

    free(HashHandle);

    memcpy(DigestList->Sha256, FinalDigest, SHA256_DIGEST_SIZE);

    return EFI_SUCCESS;
}

/* parse DOS/PE headers */
static uint64_t parse_pe_headers(uint64_t image_address,
                                 uint32_t *pe_coff_offset,
                                 efi_image_optional_header_ptr_union *hdr)
{
    efi_image_dos_header *dos_hdr = (efi_image_dos_header *)image_address;
    *pe_coff_offset = 0;

    if (dos_hdr->e_magic == EFI_IMAGE_DOS_SIGNATURE) {
        *pe_coff_offset = dos_hdr->e_lfanew;
    }

    hdr->pe32 = (efi_image_nt_headers32 *)((uint8_t *)image_address + *pe_coff_offset);
    if (hdr->pe32->signature != EFI_IMAGE_NT_SIGNATURE) {
        return EFI_UNSUPPORTED;
    }
    return EFI_SUCCESS;
}

/* Hash the image header from its base to beginning of the image checksum. */
static uint64_t hash_optional_header_part(hash_handle_t hash_handle,
                                          efi_image_optional_header_ptr_union *hdr,
                                          uint64_t image_address,
                                          size_t *sum_hashed)
{
    uint8_t *hash_base;
    size_t hash_size;
    uint32_t number_of_rva_and_sizes;
    bool is_pe32 = (hdr->pe32->optional_header.magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC);

    if (is_pe32) {
        /* Use PE32 offset */
        number_of_rva_and_sizes = hdr->pe32->optional_header.number_of_rva_and_sizes;
        hash_base = (uint8_t *)image_address;
        hash_size = ((uintptr_t)&hdr->pe32->optional_header.checksum) - ((uintptr_t)hash_base);
    } else {
        /* Use pe32+ offset */
        number_of_rva_and_sizes = hdr->pe32plus->optional_header.number_of_rva_and_sizes;
        hash_base = (uint8_t *)image_address;
        hash_size = ((uintptr_t)&hdr->pe32plus->optional_header.checksum) - ((uintptr_t)hash_base);
    }

    uint64_t status = hash_update(hash_handle, hash_base, hash_size);
    if (EFI_ERROR(status))
        return status;

    /* Skip over the image checksum */
    if (number_of_rva_and_sizes <= EFI_IMAGE_DIRECTORY_ENTRY_SECURITY) {
        uint8_t *post_checksum = (uint8_t *)&hdr->pe32->optional_header.checksum + sizeof(uint32_t);
        size_t header_size =
            is_pe32 ? hdr->pe32->optional_header.size_of_headers : hdr->pe32plus->optional_header.size_of_headers;
        hash_size = header_size - (post_checksum - (uint8_t *)image_address);

        if (hash_size > 0) {
            status = hash_update(hash_handle, post_checksum, hash_size);
        }
    } else {
        uint8_t *post_checksum = (uint8_t *)&hdr->pe32->optional_header.checksum + sizeof(uint32_t);
        size_t security_offset = is_pe32 ?
            (uintptr_t)&hdr->pe32->optional_header.data_directory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY] :
            (uintptr_t)&hdr->pe32plus->optional_header.data_directory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY];

        hash_size = security_offset - (uintptr_t)post_checksum;
        if (hash_size > 0) {
            status = hash_update(hash_handle, post_checksum, hash_size);
            if (EFI_ERROR(status))
                return status;
        }

        uint8_t *post_security = (uint8_t *)(security_offset + sizeof(efi_image_data_directory));
        size_t header_size =
            is_pe32 ? hdr->pe32->optional_header.size_of_headers : hdr->pe32plus->optional_header.size_of_headers;
        hash_size = header_size - (post_security - (uint8_t *)image_address);

        if (hash_size > 0) {
            status = hash_update(hash_handle, post_security, hash_size);
        }
    }

    *sum_hashed = is_pe32 ? hdr->pe32->optional_header.size_of_headers : hdr->pe32plus->optional_header.size_of_headers;
    return status;
}

static efi_image_section_header *copy_and_sort_sections(uint64_t image_address,
                                                        uint32_t pe_coff_offset,
                                                        efi_image_nt_headers32 *nt_header,
                                                        uint64_t *status)
{
    size_t num_sections = nt_header->file_header.number_of_sections;
    efi_image_section_header *sections = calloc(num_sections, sizeof(efi_image_section_header));
    if (!sections) {
        *status = EFI_OUT_OF_RESOURCES;
        return NULL;
    }

    uint8_t *section_base = (uint8_t *)image_address + pe_coff_offset + sizeof(uint32_t) + // Signature
        sizeof(efi_image_file_header) + nt_header->file_header.size_of_optional_header;

    memcpy(sections, section_base, num_sections * sizeof(efi_image_section_header));

    for (size_t i = 1; i < num_sections; i++) {
        efi_image_section_header temp = sections[i];
        size_t j = i;
        while (j > 0 && sections[j - 1].pointer_to_raw_data > temp.pointer_to_raw_data) {
            sections[j] = sections[j - 1];
            j--;
        }
        sections[j] = temp;
    }

    *status = EFI_SUCCESS;
    return sections;
}

static uint64_t hash_section_data(hash_handle_t hash_handle,
                                  efi_image_section_header *sections,
                                  size_t num_sections,
                                  uint64_t image_address, size_t *sum_hashed)
{
    for (size_t i = 0; i < num_sections; i++) {
        if (sections[i].size_of_raw_data == 0)
            continue;

        uint8_t *section_base = (uint8_t *)image_address + sections[i].pointer_to_raw_data;
        uint64_t status = hash_update(hash_handle, section_base, sections[i].size_of_raw_data);
        if (EFI_ERROR(status))
            return status;

        *sum_hashed += sections[i].size_of_raw_data;
    }
    return EFI_SUCCESS;
}

static uint64_t process_trailing_data(hash_handle_t hash_handle,
                                      efi_image_optional_header_ptr_union *hdr,
                                      uint64_t image_address,
                                      size_t image_size,
                                      size_t sum_hashed)
{
    uint32_t cert_size = 0;
    bool is_pe32 = (hdr->pe32->optional_header.magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC);
    uint32_t number_of_rva = is_pe32 ? hdr->pe32->optional_header.number_of_rva_and_sizes :
                                       hdr->pe32plus->optional_header.number_of_rva_and_sizes;

    if (number_of_rva > EFI_IMAGE_DIRECTORY_ENTRY_SECURITY) {
        cert_size = is_pe32 ? hdr->pe32->optional_header.data_directory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY].size :
                              hdr->pe32plus->optional_header.data_directory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY].size;
    }

    if (image_size > sum_hashed + cert_size) {
        uint8_t *trailing_base = (uint8_t *)image_address + sum_hashed;
        size_t trailing_size = image_size - sum_hashed - cert_size;
        return hash_update(hash_handle, trailing_base, trailing_size);
    }
    return EFI_SUCCESS;
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
