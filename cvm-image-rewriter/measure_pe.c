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

static uint64_t measure_pe_image_and_extend(uint64_t image_address,
                                            size_t image_size,
                                            tpml_digest_values_t *digest_list)
{
    uint64_t status;
    efi_image_optional_header_ptr_union hdr;
    uint32_t pe_coff_offset;
    hash_handle_t hash_handle = NULL;
    efi_image_section_header *sorted_sections = NULL;
    size_t sum_hashed = 0;

    /* 1. parse headers */
    if ((status = parse_pe_headers(image_address, &pe_coff_offset, &hdr)) != EFI_SUCCESS) {
        goto cleanup;
    }

    /* 2. initialize hash */
    if ((status = hash_start(&hash_handle)) != EFI_SUCCESS) {
        goto cleanup;
    }

    /* 3. parse optional headers */
    if ((status = hash_optional_header_part(hash_handle, &hdr, image_address, &sum_hashed)) != EFI_SUCCESS) {
        goto cleanup;
    }

    /* 4. copy and sort sections */
    efi_image_nt_headers32 *nt_header = hdr.pe32;
    sorted_sections = copy_and_sort_sections(image_address, pe_coff_offset, nt_header, &status);
    if (EFI_ERROR(status)) {
        goto cleanup;
    }

    /* 5. hash section data */
    if ((status = hash_section_data(hash_handle, sorted_sections, nt_header->file_header.number_of_sections,
        image_address, &sum_hashed)) != EFI_SUCCESS) {
        goto cleanup;
    }

    /* 6. process trailing data */
    if ((status = process_trailing_data(hash_handle, &hdr, image_address, image_size, sum_hashed)) != EFI_SUCCESS) {
        goto cleanup;
    }

    /* 7. finalize the SHA hash */
    status = hash_complete_and_extend(hash_handle, NULL, 0, digest_list);
    hash_handle = NULL;

cleanup:
    if (sorted_sections)
        free(sorted_sections);
    if (hash_handle)
        hash_complete_and_extend(hash_handle, NULL, 0, NULL);
    return status;
}

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
    if (!buffer) {
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
    tpml_digest_values_t digest_list;
    uint64_t status = measure_pe_image_and_extend((uint64_t)(uintptr_t)buffer, (size_t)filesize, &digest_list);
    if (status == EFI_SUCCESS) {
        printf("Measure PE image succeed, SHA-256 = ");
        for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
            printf("%02x", digest_list.sha256[i]);
        }
        printf("\n");
    } else {
        printf("Measure PE image failed, EFI_STATUS = %llu\n", (unsigned long long)status);
    }

    free(buffer);
    return 0;
}