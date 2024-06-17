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
#include "gen_rim_ref.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#if LOG_PRINT
int data_measure_cnt = 0;
int data_unknown_cnt = 0;
#endif

static size_t get_file_size(const char *filename)
{
	FILE *file = fopen(filename, "rb");
	if (file == NULL) {
		return -1;
	}

	fseek(file, 0, SEEK_END);
	size_t size = ftell(file);
	fclose(file);

	return size;
}

static inline size_t measurement_get_size(
					const enum hash_algo algorithm)
{
	size_t ret = 0;
	switch (algorithm) {
	case HASH_ALGO_SHA256:
		ret = (size_t)SHA256_SIZE;
		break;
	case HASH_ALGO_SHA512:
		ret = (size_t)SHA512_SIZE;
		break;
	default:
		assert(false);
	}
	return ret;
}

static uint32_t get_bootloader_aarch64(uint64_t kernel_start,
									   uint64_t dtb_start,
									   uint32_t *code)
{
	uint32_t bootloader[BOOTLOADER_LEN_UINT32];
	bootloader[0] = 0x580000c0; /* 0x 58 00 00 c0      ; ldr x0, arg ; Load the lower 32-bits of DTB */
	bootloader[1] = 0xaa1f03e1; /* 0x aa 1f 03 e1      ; mov x1, xzr */
	bootloader[2] = 0xaa1f03e2; /* 0x aa 1f 03 e2      ; mov x2, xzr */
	bootloader[3] = 0xaa1f03e3; /* 0x aa 1f 03 e3      ; mov x3, xzr */
	bootloader[4] = 0x58000084; /* 0x 58 00 00 84      ; ldr x4, entry ; Load the lower 32-bits of kernel entry */
	bootloader[5] = 0xd61f0080; /* 0x d6 1f 00 80      ; br x4      ; Jump to the kernel entry point */
	/* FIXUP_ARGPTR_LO   ; arg: .word @DTB Lower 32-bits */
	bootloader[6] = dtb_start;
	/* FIXUP_ARGPTR_HI     ; .word @DTB Higher 32-bits */
	bootloader[7] = dtb_start >> 32;
	/* FIXUP_ENTRYPOINT_LO ; entry: .word @Kernel Entry Lower 32-bits */
	bootloader[8] = kernel_start;
	/* FIXUP_ENTRYPOINT_HI ; .word @Kernel Entry Higher 32-bits */
	bootloader[9] = kernel_start >> 32;
	memcpy(code, bootloader, BOOTLOADER_LEN_UINT32 * sizeof(uint32_t));
}

void print_hash(unsigned char *measurement,
			    const enum hash_algo algorithm)
{
	unsigned int size = 0U;
	assert(measurement != NULL);
	char hexDigits[] = "0123456789ABCDEF";
	int hexIndex = 0;

	char hash_str[130] = "";

	switch (algorithm) {
	case HASH_ALGO_SHA256:
		size = SHA256_SIZE;
		break;
	case HASH_ALGO_SHA512:
		size = SHA512_SIZE;
		break;
	default:
		assert(0);
	}

	for (unsigned int i = 0U; i < size; ++i) {
		hash_str[hexIndex++] = hexDigits[*(measurement+i) >> 4 & 0x0F];
		hash_str[hexIndex++] = hexDigits[*(measurement+i) & 0x0F];
	}

	printf("HASH: %s\n", hash_str);
}

static void print_data(unsigned char *data)
{
	char hexDigits[] = "0123456789ABCDEF";
	int hexIndex = 0;

	char output[130] = "";

	for (unsigned int i = 0; i < 32; ++i) {
		output[hexIndex++] = hexDigits[*(data+i) >> 4 & 0x0F];
		output[hexIndex++] = hexDigits[*(data+i) & 0x0F];
	}

	printf("DATA: %s\n", output);
}

static int do_hash(enum hash_algo hash_algo,
		    void *data,
		    size_t size,
		    unsigned char *out)
{
	int result = 0;
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	unsigned int md_len;

	OpenSSL_add_all_digests();

	switch (hash_algo) {
		case HASH_ALGO_SHA256:
			md = EVP_sha256();
			break;
		case HASH_ALGO_SHA512:
			md = EVP_sha512();
			break;
		default:
			printf("Unspported hash algorithnm\n");
			return 1;
	}

	mdctx = EVP_MD_CTX_new();
	if (mdctx == NULL) {
		printf("Failed to initialiaze digest contex\n");
		return 2;
	}

	if (EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
		printf("Failed to initialize digest\n");
		result = 3;
	} else if (EVP_DigestUpdate(mdctx, data, size) != 1) {
		printf("Failed to update digest\n");
		result = 4;
	} else if (EVP_DigestFinal_ex(mdctx, out, &md_len) != 1) {
		printf("Failed to finalize digest\n");
		result = 5;
	}
	EVP_MD_CTX_free(mdctx);

	#if LOG_PRINT
	print_hash(out, hash_algo);
	#endif

	return result;
}

void measure_tmi_cvm_create(cvm_init_measure_t *meas, tmi_cvm_create_params_t *params)
{
    /* Allocate a zero-filled tmi_measure_cvm_t data structure to hold
    the measured cVM parameters. By specification cVM_params is 4KB. */
    unsigned char buffer[sizeof(tmi_measure_cvm_t)] = {0};
    tmi_measure_cvm_t *tmm_params_measured = (tmi_measure_cvm_t *)buffer;

    /*
	 * Copy flags, s2sz, sve_vl, num_bps, num_wps, pmu_num_cnts
     * and hash_algo to the measured cVM parameters.
	 */
	tmm_params_measured->flags = params->flags;
	tmm_params_measured->s2sz = params->s2sz;
	tmm_params_measured->sve_vl = params->sve_vl;
	tmm_params_measured->num_bps = params->num_bps;
	tmm_params_measured->num_wps = params->num_wps;
	tmm_params_measured->pmu_num_cnts = params->pmu_num_cnts;
	tmm_params_measured->measurement_algo = params->measurement_algo;

	meas->measurement_algo = params->measurement_algo;

	#if LOG_PRINT
	printf("Measuring tmi_cvm_create\n");
	printf("flags:   0x%016lx\n", params->flags);
	printf("s2sz:    0x%016lx\n", params->s2sz);
	printf("sve_vl:  0x%016lx\n", params->sve_vl);
	printf("num_bps: 0x%016lx\n", params->num_bps);
	printf("num_wps: 0x%016lx\n", params->num_wps);
	printf("pmu_cnt: 0x%016lx\n", params->pmu_num_cnts);
	printf("h-algo:  0x%016lx\n", params->measurement_algo);
	#endif

    /* Compute the HASH on tmm_params_measured data structurem, set the RIM to
       this value, zero filling the upper bytes if the HASH output is smaller
       than the size of the RIM. */
    do_hash(meas->measurement_algo, buffer, sizeof(buffer), meas->rim);
}

void measure_tmi_tec_create(cvm_init_measure_t *meas, tmi_tec_create_params_t *params)
{
    /* Allocate a zero_filled TmiTecParams data structure to hold the measured
    TEC parametsrs. */
	unsigned char buffer[sizeof(tmi_tec_params_t)] = {0};
    tmi_tec_params_t *tec_params_measured = (tmi_tec_params_t *)buffer;

    /* Copy gprs, pc, flags into the measured TEC parameters data structure */
    tec_params_measured->pc = params->pc;
	tec_params_measured->flags = params->flags;
	memcpy(tec_params_measured->gprs, params->gprs, sizeof(params->gprs));

	#if LOG_PRINT
	printf("Measuring tmi_tec_create\n");
	printf("pc:      0x%016lx\n", tec_params_measured->pc);
	printf("flags:   0x%016lx\n", tec_params_measured->flags);
	printf("gprs[0]: 0x%016lx\n", tec_params_measured->gprs[0]);
	printf("gprs[1]: 0x%016lx\n", tec_params_measured->gprs[1]);
	printf("gprs[2]: 0x%016lx\n", tec_params_measured->gprs[2]);
	printf("gprs[3]: 0x%016lx\n", tec_params_measured->gprs[3]);
	printf("gprs[4]: 0x%016lx\n", tec_params_measured->gprs[4]);
	printf("gprs[5]: 0x%016lx\n", tec_params_measured->gprs[5]);
	printf("gprs[6]: 0x%016lx\n", tec_params_measured->gprs[6]);
	printf("gprs[7]: 0x%016lx\n", tec_params_measured->gprs[7]);
	#endif

    /* Initialize the measurement descriptor structure and populate the descriptor */
    tmi_measure_tec_t measure_desc = {0};
    /* Set the desc_type field to the descriptor type */
    measure_desc.desc_type = MEASURE_DESC_TYPE_REC;
    /* Set the len field to the descriptor length */
    measure_desc.len = sizeof(tmi_measure_tec_t);
    /* Set the rim field to the current RIM value of the target cVM */
    memcpy(measure_desc.rim, meas->rim, measurement_get_size(meas->measurement_algo));
    /* Set the content field to the hash of the measured REC parameters */
    do_hash(meas->measurement_algo, tec_params_measured, sizeof(*tec_params_measured), measure_desc.content);

    /* Hashing the measurement descriptor structure and get the new RIM */
    do_hash(meas->measurement_algo, &measure_desc, sizeof(measure_desc), meas->rim);
}

void measure_tmi_data_create(cvm_init_measure_t *meas, tmi_data_create_params_t *params)
{

    /* Allocate an TmiMeasurementDescriptorData data structure */
    tmi_measure_data_t measure_desc = {0};

	/* Initialize the measurement descriptior structure */
    /* Set the desc_type field to the descriptor type */
	measure_desc.desc_type = MEASURE_DESC_TYPE_DATA;
    /* Set the len field to the descriptor length */
	measure_desc.len = sizeof(tmi_measure_data_t);
    /* Set the ipa field to the IPA at which the DATA Granule is mapped in the target cVM */
	measure_desc.ipa = params->ipa;
    /* Set the flags field to the flags */
	measure_desc.flags = params->flags;
    /* Set the rim field to the current RIM value of the target cVM */
	(void)memcpy(measure_desc.rim, meas->rim, measurement_get_size(meas->measurement_algo));

    /* If flags.measure == TMI_MEASURE_CONTENT then set the content field to the hash of
     * the contents of the DATA Granule. Otherwise, set the content field to zero.
     */
    if (measure_desc.flags == TMI_MEASURE_CONTENT) {
		/*
		 * Hashing the data granules and store the result in the
		 * measurement descriptor structure.
		 */
		#if LOG_PRINT
		data_measure_cnt ++;
		printf("Measuring tmi_data_create %d\n", data_measure_cnt);
		print_data((unsigned char *)params->data);
		#endif

		do_hash(meas->measurement_algo, params->data, (size_t)params->size, measure_desc.content);
	} else {
		#if LOG_PRINT
		data_unknown_cnt ++;
		printf("Measuring tmi_data_create_unknown %d\n", data_unknown_cnt);
		#endif
	}

	#if LOG_PRINT
	printf("ipa:     0x%016lx\n", params->ipa);
	printf("size:    0x%016lx\n", params->size);
	printf("flags:   0x%016lx\n", params->flags);
	#endif

	/*
	 * Hashing the measurement descriptor structure; the result is the
	 * updated RIM.
	 */
	do_hash(meas->measurement_algo, &measure_desc, sizeof(measure_desc), meas->rim);
}

void measure_load_data(cvm_init_measure_t *meas,
					   uint64_t loader_start,
					   uint64_t ram_size,
					   uint64_t initrd_start,
					   const char *kernel_path,
					   const char *initramfs_path,
					   const char *dtb_path)
{
	FILE *file;
	size_t initrd_size;
	size_t dtb_size;

	if (initramfs_path == NULL) {
		initrd_size = 0;
	} else {
		initrd_size = get_file_size(initramfs_path);
		if (initrd_size < 0) {
			perror("Cannot open initramfs file");
			return;
		}
	}

	size_t bytes_read;
	size_t addr =  round_down(loader_start, BLOCK_SIZE);
	size_t addr_end = round_up(loader_start + ram_size, BLOCK_SIZE);
	size_t kernel_start = loader_start + KERNEL_LOAD_OFFSET;
	size_t dtb_start = round_up(initrd_start + initrd_size, BLOCK_SIZE);
	tmi_data_create_params_t params;
    unsigned char *buffer;

	buffer = malloc(BLOCK_SIZE);
	if (buffer == NULL) {
		perror("Memory allocation error");
		return;
	}

	/* Measure bootloader */
	uint32_t code[BOOTLOADER_LEN_UINT32];
	get_bootloader_aarch64(kernel_start, dtb_start, code);
	memset(buffer, 0, sizeof(buffer));
	memcpy(buffer, code, sizeof(code));
	for (uint64_t i = 0; i < BLOCK_SIZE / 4096; i++)
	{
		memset(&params, 0, sizeof(params));
		params.data = (uint64_t *)(buffer + i * 4096);
		params.size = 4096;
		SET_BIT(params.flags, 0);
		params.ipa = addr + i * 4096;
		measure_tmi_data_create(meas, &params);
	}
	addr += L2_GRANULE;

	/* Measure kernel*/
	uint64_t kernel_size_k = 0;
	int size;
	uint8_t *buffer_k_tmp;
	gsize len;
	unsigned char *buffer_k = NULL;

	if (!g_file_get_contents(kernel_path, (char **)&buffer_k_tmp, &len, NULL)) {
		perror("Error open kernel file");
		return;
	}
	size = len;
	if (size > ARM64_MAGIC_OFFSET + 4 &&
		memcmp(buffer_k_tmp + ARM64_MAGIC_OFFSET, "ARM\x64", 4) == 0) {
		uint64_t hdrvals[2];
		memcpy(&hdrvals, buffer_k_tmp + ARM64_TEXT_OFFSET_OFFSET, sizeof(hdrvals));
		kernel_size_k = hdrvals[1];
		kernel_size_k = round_up(kernel_size_k, L3_GRANULE);
	}
	buffer_k = (unsigned char *)malloc(kernel_size_k);
	if (buffer_k == NULL) {
		perror("malloc buffer for kernel failed.");
		free(buffer_k_tmp);
		return;
	}
	memset(buffer_k, 0, kernel_size_k);
	memcpy(buffer_k, buffer_k_tmp, size);
	free(buffer_k_tmp);

	for (uint64_t i = 0; i < kernel_size_k / L3_GRANULE; i++) {
		memset(&params, 0, sizeof(params));
		params.data = (uint64_t *)(buffer_k + i * 4096);
		params.size = 4096;
		SET_BIT(params.flags, 0);
		params.ipa = addr + i * 4096;
		measure_tmi_data_create(meas, &params);
	}

	/* Useless measurement */
    addr = initrd_start;

	/* Measure initramfs*/
	if (initrd_size != 0) {
		file = fopen(initramfs_path, "rb");
		if (file == NULL) {
			perror("Error opening initramfs file");
			return;
		}

		while (!feof(file)) {
			bytes_read = fread(buffer, 1, BLOCK_SIZE, file);
			if (bytes_read < BLOCK_SIZE) {
				if (ferror(file)) {
					perror("Error reading initramfs file");
					break;
				}
				memset(buffer + bytes_read, 0, BLOCK_SIZE - bytes_read);
			}

			for (uint64_t i = 0; i < BLOCK_SIZE / 4096; i++)
			{
				memset(&params, 0, sizeof(params));
				params.data = (uint64_t *)(buffer + i * 4096);
				params.size = 4096;
				SET_BIT(params.flags, 0);
				params.ipa = addr + i * 4096;
				measure_tmi_data_create(meas, &params);
			}
			addr += BLOCK_SIZE;
		}
	}

	/* Measure dtb*/
	file = fopen(dtb_path, "rb");
	if (file == NULL) {
		perror("Error opening dtb file");
		return;
	}

	while (!feof(file)) {
		bytes_read = fread(buffer, 1, BLOCK_SIZE, file);
		if (bytes_read < BLOCK_SIZE) {
			if (ferror(file)) {
				perror("Error reading dtb file");
				break;
			}
			memset(buffer + bytes_read, 0, BLOCK_SIZE - bytes_read);
		}

		for (uint64_t i = 0; i < BLOCK_SIZE / 4096; i++)
		{
			memset(&params, 0, sizeof(params));
			params.data = (uint64_t *)(buffer + i * 4096);
			params.size = 4096;
			SET_BIT(params.flags, 0);
			params.ipa = addr + i * 4096;
			measure_tmi_data_create(meas, &params);
		}
		addr += BLOCK_SIZE;

	}

}

void measure_create_tecs(cvm_init_measure_t *meas,
					     uint64_t loader_start,
						 unsigned int tec_num)
{
	tmi_tec_create_params_t params;

	for (size_t i = 0; i < tec_num; i++)
	{
		memset(&params, 0, sizeof(params));
		if (i == 0) { /* The master tec */
			params.pc = loader_start;
			SET_BIT(params.flags, 0);
		}
		measure_tmi_tec_create(meas, &params);
	}

}

void measure_create_cvm(cvm_init_measure_t *meas,
						bool lpa2_enable,
						bool sve_enable,
						bool pmu_enable,
						uint64_t ipa_width,
						uint64_t sve_vector_length,
						uint64_t num_bps,
						uint64_t num_wps,
						uint64_t num_pmu,
						uint64_t hash_algo)
{
	tmi_cvm_create_params_t params = {0};
	if (lpa2_enable) {
		SET_BIT(params.flags, 0);
	} else {
		CLEAR_BIT(params.flags, 0);
	}

	if (sve_enable) {
		SET_BIT(params.flags, 1);
	} else {
		CLEAR_BIT(params.flags, 1);
	}

	if (pmu_enable) {
		SET_BIT(params.flags, 2);
	} else {
		CLEAR_BIT(params.flags, 2);
	}

	params.s2sz 			= ipa_width;
	params.sve_vl 			= sve_vector_length;
	params.num_bps 			= num_bps;
	params.num_wps 			= num_wps;
	params.pmu_num_cnts 	= num_pmu;
	params.measurement_algo = hash_algo;

	measure_tmi_cvm_create(meas, &params);
}

void generate_rim_reference(const char *kernel_path, const char *dtb_path,
							const char *initramfs_path)
{
	bool lpa2_enable = false;
	bool sve_enable = true;
	bool pmu_enable = true;
	uint64_t ipa_width = 40;
	uint64_t sve_vector_length = 1;
	uint64_t num_bps = 0;
	uint64_t num_wps = 0;
	uint64_t num_pmu = 1;
	uint64_t hash_algo = 0;
	uint64_t tec_num = 1;
	uint64_t loader_start = LOADER_START_ADDR;
	uint64_t ram_size = 1024 * MB;
	uint64_t initrd_start = 128 * MB + loader_start;

	cvm_init_measure_t meas={0};
	measure_create_cvm(&meas, lpa2_enable, sve_enable, pmu_enable,
					   ipa_width, sve_vector_length, num_bps, num_wps,
					   num_pmu, hash_algo);
	measure_load_data(&meas, loader_start, ram_size, initrd_start,
					  kernel_path, initramfs_path, dtb_path);
	measure_create_tecs(&meas, loader_start, tec_num);
	printf("RIM-");
	print_hash(meas.rim, meas.measurement_algo);
}

void print_help()
{
    printf("Generate rim reference value:\n");
    printf("  <kernel_path> <dtb_path> [<initramfs_path>] \n");
	printf("        kernel_path:     path to kernel image\n");
    printf("        dtb_path:        path to device tree dtb file\n");
	printf("        initramfs_path:  path to initramfs gzip file\n");
}

int main(int argc, char *argv[])
{
    int ret = 0;

	/* Parse parameters based on inputted ini config file */

    if (argc < 2) {
        errno = EINVAL;
        perror("Please input kernel path and dtb path");
        print_help();
        return -1;
    }

	if (argc < 3) {
        errno = EINVAL;
        perror("Please input dtb path");
        print_help();
        return -1;
    }

	char kernel_path[1000];
	char dtb_path[1000];
	char initramfs_path[1000];
	strncpy(kernel_path, argv[1], sizeof(kernel_path));
	strncpy(dtb_path, argv[2], sizeof(dtb_path));
	if (argc < 4) {
		generate_rim_reference(kernel_path, dtb_path, NULL);
	} else {
		strncpy(initramfs_path, argv[3], sizeof(initramfs_path));
		generate_rim_reference(kernel_path, dtb_path, initramfs_path);
	}

	return ret;

}