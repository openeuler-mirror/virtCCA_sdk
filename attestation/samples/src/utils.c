#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/limits.h>
#include "utils.h"

#define CMDLINE_SIZE 1000

int hex_to_bytes(unsigned char *in, size_t in_len, unsigned char *out, size_t *out_len)
{
    int i;

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
    if (count >= CMDLINE_SIZE) {
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
