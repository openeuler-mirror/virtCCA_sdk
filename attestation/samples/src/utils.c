#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/limits.h>
#include "utils.h"

#define CMDLINE_SIZE 1000

int hex_to_bytes(unsigned char *in, size_t in_len, unsigned char *out, size_t *out_len)
{
    size_t i;

    if (in == NULL || out == NULL || out_len == NULL) {
        printf("Param is NULL.");
        return 1;
    }
    if (in_len % 2 != 0 || in_len / 2 > *out_len) {
        printf("Invalid input size.\n");
        return 1;
    }
    for (i = 0; i < in_len / 2; i++) {
        if (sscanf(in + i * 2, "%2hhx", out + i) != 1) {
            printf("Invalid input.\n");
            return 1;
        }
    }
    *out_len = i;

    return 0;
}

int download_cert_pem(const char *prefix, const char *filename, const char *url)
{
    int count = 0;
    char cmdline_str[CMDLINE_SIZE] = {0};

    count = snprintf(cmdline_str, sizeof(cmdline_str), "wget -O %s/%s %s",
                     prefix, filename, url);
    if (count >= CMDLINE_SIZE || count <= 0) {
        printf("Param too long.\n");
        return 1;
    }

    if (!file_exists(prefix, filename)) {
        if (system(cmdline_str) != 0) {
            printf("Failed to download %s/%s\n", prefix, filename);
            return 1;
        }
    }

    return 0;
}

int file_exists(const char *prefix, const char *filename)
{
    char fullpath[PATH_MAX] = {0};
    snprintf(fullpath, sizeof(fullpath), "%s/%s", prefix, filename);
    return access(fullpath, F_OK) == 0;
}

/*
 * Read file data into a dynamically allocated buffer
 * Caller is responsible for freeing the allocated memory
 */
int read_file_data(const char *file_name, unsigned char **file_data, size_t *file_size)
{
    FILE *file = fopen(file_name, "rb");
    if (file == NULL) {
        printf("Failed to open file %s.\n", file_name);
        return 1;
    }

    fseek(file, 0, SEEK_END);
    *file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    *file_data = (unsigned char *)malloc(*file_size + 1);
    if (file_data == NULL) {
        printf("Failed to allocate memory.\n");
        fclose(file);
        return 1;
    }

    size_t byte_read = fread(*file_data, 1, *file_size, file);
    if (byte_read != *file_size) {
        printf("Failed to read opened file.\n");
        free(*file_data);
        fclose(file);
        return 1;
    }

    fclose(file);
    return 0;
}

/*
 * Alternative file reading utility for binary files
 * Returns a pointer to allocated memory containing file data
 * Caller is responsible for freeing the memory
 */
uint8_t* read_file_data_binary(const char* filename, size_t* out_size)
{
    if (!filename || !out_size) {
        return NULL;
    }

    /* Open file */
    FILE* fp = fopen(filename, "rb");
    if (!fp) {
        printf("Error: Could not open file: %s\n", filename);
        return NULL;
    }

    /* Get file size */
    fseek(fp, 0, SEEK_END);
    size_t file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    /* Allocate memory */
    uint8_t* data = (uint8_t*)malloc(file_size);
    if (!data) {
        printf("Error: Failed to allocate memory for file data\n");
        fclose(fp);
        return NULL;
    }

    /* Read data */
    if (fread(data, 1, file_size, fp) != file_size) {
        printf("Error: Failed to read file data\n");
        free(data);
        fclose(fp);
        return NULL;
    }

    fclose(fp);
    *out_size = file_size;
    return data;
}

/*
 * Save data to a file
 */
int save_file_data(const char *file_name, unsigned char *file_data, size_t file_size)
{
    FILE *file = fopen(file_name, "wb");
    if (file == NULL) {
        printf("Failed to open file %s\n", file_name);
        return 1;
    }

    size_t byte_write = fwrite(file_data, 1, file_size, file);
    if (byte_write != file_size) {
        printf("Failed to write opened file");
        fclose(file);
        return 1;
    }

    fclose(file);
    return 0;
}

/*
 * Read text file utility function
 * Returns a pointer to allocated memory containing null-terminated text
 * Caller is responsible for freeing the memory
 */
char* read_text_file(const char* filename, size_t* out_size)
{
    if (!filename || !out_size) {
        return NULL;
    }

    /* Open file */
    FILE* fp = fopen(filename, "r");
    if (!fp) {
        printf("Error: Could not open file: %s\n", filename);
        return NULL;
    }

    /* Get file size */
    fseek(fp, 0, SEEK_END);
    size_t file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    /* Allocate memory (add 1 for null terminator) */
    char* data = (char*)malloc(file_size + 1);
    if (!data) {
        printf("Error: Failed to allocate memory for file data\n");
        fclose(fp);
        return NULL;
    }

    /* Read data */
    if (fread(data, 1, file_size, fp) != file_size) {
        printf("Error: Failed to read file data\n");
        free(data);
        fclose(fp);
        return NULL;
    }

    /* Add null terminator */
    data[file_size] = '\0';

    fclose(fp);
    *out_size = file_size;
    return data;
}
