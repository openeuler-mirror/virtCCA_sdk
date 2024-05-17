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

#define MAX_MEASURMENT_SIZE 64

unsigned char challenge[CHALLENGE_SIZE] = {};
unsigned char measurment[MAX_MEASURMENT_SIZE] = {};
size_t measurment_len = MAX_MEASURMENT_SIZE;

int verify_token(unsigned char *token, size_t token_len)
{
    bool ret;
    cca_token_t cca_token;
    cert_info_t cert_info;

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

    if (cca_token.cvm_token.rim.len != measurment_len ||
        memcmp(cca_token.cvm_token.rim.ptr, measurment, measurment_len)) {
        printf("Failed to verify measurment.\n");
        return VERIFY_FAILED;
    }

    if (cca_token.cvm_token.challenge.len != CHALLENGE_SIZE ||
        memcmp(cca_token.cvm_token.challenge.ptr, challenge, CHALLENGE_SIZE)) {
        printf("Failed to verify challenge.\n");
        return VERIFY_FAILED;
    }

    ret = verify_cca_token_signatures(&cert_info,
                                cca_token.cvm_cose,
                                cca_token.cvm_token.pub_key,
                                cca_token.cvm_token.pub_key_hash_algo_id);
    if (!ret) {
        return VERIFY_FAILED;
    }
    return VERIFY_SUCCESS;
}

int save_dev_cert(const char *prefix, const char * filename, const char *dev_cert, const size_t dev_cert_len)
{
    char fullpath[PATH_MAX] = {0};
    FILE *fp = NULL;

    snprintf(fullpath, sizeof(fullpath), "%s/%s", prefix, filename);
    fp = fopen(fullpath, "wb");
    if (!fp) {
        printf("Cannot open dev cert file %s\n", fullpath);
        return 1;
    }

    X509 *aik = X509_new();
    aik = d2i_X509(&aik, (const unsigned char **)&dev_cert, dev_cert_len);
    PEM_write_X509(fp, aik);

    X509_free(aik);
    fclose(fp);
    return 0;
}

int handle_connect(int sockfd)
{
    int ret;
    int n;
    enum MSG_ID msg_id;
    unsigned char buf[MAX] = {};
    size_t dev_cert_len = 0;

    msg_id = DEVICE_CERT_MSG_ID;
    write(sockfd, &msg_id, sizeof(msg_id));

    dev_cert_len = read(sockfd, buf, MAX);

    save_dev_cert(DEFAULT_CERT_PEM_PREFIX, DEFAULT_AIK_CERT_PEM_FILENAME, buf, dev_cert_len);

    msg_id = ATTEST_MSG_ID;
    RAND_priv_bytes(challenge, CHALLENGE_SIZE);

    memcpy(buf, &msg_id, sizeof(msg_id));
    memcpy(buf + sizeof(msg_id), challenge, CHALLENGE_SIZE);
    write(sockfd, buf, sizeof(msg_id) + CHALLENGE_SIZE);

    unsigned char token[MAX] = {};
    size_t token_len = 0;
    token_len = read(sockfd, token, sizeof(token));

    ret = verify_token(token, token_len);
    if (ret == VERIFY_SUCCESS) {
        msg_id = VERIFY_SUCCESS_MSG_ID;
    } else {
        msg_id = VERIFY_FAILED_MSG_ID;
    }

    write(sockfd, &msg_id, sizeof(msg_id));
    return ret;
}

void print_usage(char *name)
{
    printf("Usage: %s [options]\n", name);
    printf("Options:\n");
    printf("-i, --ip <ip>                    ip\n");
    printf("-p, --port <port>                port\n");
    printf("-m, --measurment <measurment>    measurment\n");
    printf("-h, --help                       Print Help (this message) and exit\n");
}

int main(int argc, char *argv[])
{
    int ret = 1;
    int sockfd, connfd;
    struct sockaddr_in servaddr, cli;

    int ip = htonl(INADDR_LOOPBACK);
    int port = htons(PORT);
    unsigned char *measurment_hex = "";

    int option;
    struct option const long_options[] = {
        { "ip", required_argument, NULL, 'i' },
        { "port", required_argument, NULL, 'p' },
        { "measurment", required_argument, NULL, 'm' },
        { "help", no_argument, NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };
    while (1) {
        int option_index = 0;
        option = getopt_long(argc, argv, "i:p:m:h", long_options, &option_index);
        if (option == -1) {
            break;
        }
        switch (option) {
        case 'i':
            ip = inet_addr(optarg);
            break;
        case 'p':
            port = htons(atoi(optarg));
            break;
        case 'm':
            measurment_hex = optarg;
            if (hex_to_bytes(measurment_hex, strlen(measurment_hex), measurment, &measurment_len) != 0) {
                printf("Invalid measurment.\n");
                exit(1);
            }
            break;
        case 'h':
            print_usage(argv[0]);
        default:
            fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
            exit(1);
        }

    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("socket creation failed...\n");
        return ret;
    }
    else
        printf("Socket successfully created..\n");
    bzero(&servaddr, sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = ip;
    servaddr.sin_port = port;

    if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0) {
        printf("connection with the server failed...\n");
        return ret;
    }
    else
        printf("connected to the server..\n");

    ret = handle_connect(sockfd);

    close(sockfd);
    return ret;
}
