#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stddef.h>

int hex_to_bytes(unsigned char *in, size_t in_len, unsigned char *out, size_t *out_len);
int download_cert_pem(const char *prefix, const char *filename, const char *url);
int file_exists(const char *prefix, const char *filename);

#endif /* UTILS_H */
