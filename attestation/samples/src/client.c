#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>
#include <getopt.h>
#include <linux/limits.h>

#include "token_parse.h"
#include "token_validate.h"
#include "utils.h"
#include "common.h"

#include "openssl/rand.h"
#include "openssl/x509.h"
#include "openssl/pem.h"


static int verify_token(unsigned char *token, size_t token_len, client_args *args)
{
    bool ret;
    cca_token_t cca_token = {0};
    cert_info_t cert_info = {0};

    ret = parse_cca_attestation_token(&cca_token, token, token_len);
    if (ret != VIRTCCA_SUCCESS) {
        printf("Failed to parse attestation token.\n");
        return VERIFY_FAILED;
    }
    print_cca_attestation_token_raw(&cca_token);
    print_cca_attestation_token(&cca_token);

    strcpy(cert_info.cert_path_prefix, DEFAULT_CERT_PEM_PREFIX);
    strcpy(cert_info.root_cert_filename, DEFAULT_ROOT_CERT_PEM_FILENAME);
    strcpy(cert_info.sub_cert_filename, DEFAULT_SUB_CERT_PEM_FILENAME);
    strcpy(cert_info.aik_cert_filename, DEFAULT_AIK_CERT_PEM_FILENAME);
    strcpy(cert_info.root_cert_url, DEFAULT_ROOT_CERT_URL);
    strcpy(cert_info.sub_cert_url, DEFAULT_SUB_CERT_URL);

    if (cca_token.cvm_token.rim.len != args->meas_len ||
        memcmp(cca_token.cvm_token.rim.ptr, args->measurement, args->meas_len)) {
        printf("Failed to verify measurement.\n");
        return VERIFY_FAILED;
    }

    if (cca_token.cvm_token.challenge.len != CHALLENGE_SIZE ||
        memcmp(cca_token.cvm_token.challenge.ptr, args->challenge, CHALLENGE_SIZE)) {
        printf("Failed to verify challenge.\n");
        return VERIFY_FAILED;
    }

    ret = verify_cca_token_signatures(&cert_info,
                                cca_token.cvm_cose,
                                cca_token.cvm_token.pub_key);
    if (!ret) {
        return VERIFY_FAILED;
    }
    return VERIFY_SUCCESS;
}

static int save_dev_cert(const char *prefix, const char * filename, const char *dev_cert, const size_t dev_cert_len)
{
    char fullpath[PATH_MAX] = {0};
    FILE *fp = NULL;
    X509 *aik = NULL;
    int ret = -1;

    snprintf(fullpath, sizeof(fullpath), "%s/%s", prefix, filename);
    fp = fopen(fullpath, "wb");
    if (!fp) {
        printf("Cannot open dev cert file %s\n", fullpath);
        return 1;
    }

    aik = d2i_X509(NULL, (const unsigned char **)&dev_cert, dev_cert_len);
    if (!aik) {
        printf("create x509 failed.\n");
        goto close;
    }
    if (PEM_write_X509(fp, aik) != 1) {
        printf("write dev cert file failed.\n");
    } else {
        ret = 0;
    }

    X509_free(aik);
close:
    fclose(fp);
    return ret;
}

static int handle_connect(int sockfd, client_args *args)
{
    int ret = -1;
    enum MSG_ID msg_id;
    unsigned char buf[MAX] = {0};
    ssize_t len = 0;

    msg_id = DEVICE_CERT_MSG_ID;
    if (write(sockfd, &msg_id, sizeof(msg_id)) != sizeof(msg_id)) {
        printf("write msg id failed\n");
        return ret;
    }

    if ((len = read(sockfd, buf, MAX)) <= 0) {
        printf("read data failed.\n");
        return ret;
    }
    if (save_dev_cert(DEFAULT_CERT_PEM_PREFIX, DEFAULT_AIK_CERT_PEM_FILENAME, buf, len)) {
        return ret;
    }

    msg_id = ATTEST_MSG_ID;
    RAND_priv_bytes(args->challenge, CHALLENGE_SIZE);

    memcpy(buf, &msg_id, sizeof(msg_id));
    memcpy(buf + sizeof(msg_id), args->challenge, CHALLENGE_SIZE);
    if (write(sockfd, buf, sizeof(msg_id) + CHALLENGE_SIZE) != sizeof(msg_id) + CHALLENGE_SIZE) {
        printf("write challenge failed\n");
        return ret;
    }

    unsigned char token[MAX] = {};
    if ((len = read(sockfd, token, sizeof(token))) <= 0) {
        printf("read data failed.\n");
        return ret;
    }

    ret = verify_token(token, len, args);
    if (ret == VERIFY_SUCCESS) {
        msg_id = VERIFY_SUCCESS_MSG_ID;
        ret = 0;
    } else {
        msg_id = VERIFY_FAILED_MSG_ID;
    }

    if (write(sockfd, &msg_id, sizeof(msg_id)) != sizeof(msg_id)) {
        printf("write back id failed.\n");
        ret = -1;
    }
    return ret;
}

static void print_usage(char *name)
{
    printf("Usage: %s [options]\n", name);
    printf("Options:\n");
    printf("\t-i, --ip <ip>                      Listening IP address\n");
    printf("\t-p, --port <port>                  Listening tcp port\n");
    printf("\t-m, --measurement <measurement>    Initial measurement for cVM\n");
    printf("\t-h, --help                         Print Help (this message) and exit\n");
}

static int parse_args(int argc, char *argv[], client_args *args)
{
    int option, len;
    int option_index = 0;

    args->meas_len = MAX_MEASUREMENT_SIZE;
    args->ip = htonl(INADDR_LOOPBACK);
    args->port = htons(PORT);

    struct option const long_options[] = {
        { "ip", required_argument, NULL, 'i' },
        { "port", required_argument, NULL, 'p' },
        { "measurement", required_argument, NULL, 'm' },
        { "help", no_argument, NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };
    while ((option = getopt_long(argc, argv, "i:p:m:h", long_options, &option_index)) != -1) {
        switch (option) {
            case 'i':
                args->ip = inet_addr(optarg);
                break;
            case 'p':
                args->port = htons(atoi(optarg));
                break;
            case 'm':
                len = strnlen(optarg, MAX_MEASUREMENT_HEX_SIZE + 1);
                if (len == MAX_MEASUREMENT_HEX_SIZE + 1 ||
                    hex_to_bytes(optarg, len, args->measurement, (size_t *)&args->meas_len) != 0) {
                    printf("Invalid measurement.\n");
                    return -1;
                }
                break;
            default:
                print_usage(argv[0]);
                return -1;
        }
    }
    return 0;
}

int main(int argc, char *argv[])
{
    int ret = 1;
    int sockfd = -1;
    struct sockaddr_in servaddr;
    client_args args = {0};
    if (parse_args(argc, argv, &args)) {
        return ret;
    }
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("socket creation failed...\n");
        return ret;
    } else {
        printf("Socket successfully created..\n");
    }

    bzero(&servaddr, sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = args.ip;
    servaddr.sin_port = args.port;

    if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0) {
        printf("connection with the server failed...\n");
        goto close;
    } else {
        printf("connected to the server..\n");
    }

    ret = handle_connect(sockfd, &args);

close:
    close(sockfd);
    return ret;
}
