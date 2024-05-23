#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <getopt.h>
#include "attestation.h"
#include "common.h"

int handle_connect(int connfd, tsi_ctx *ctx)
{
    int ret;
    unsigned char buff[MAX];
    int n;
    enum MSG_ID msg_id;

    int major, minor;
    ret = get_version(ctx, &major, &minor);
    if (ret != TSI_SUCCESS) {
        printf("Failed to get TSI version.\n");
        return ret;
    }
    printf("TSI version %d.%d advertised\n", major, minor);

    for (;;) {
        bzero(buff, MAX);

        read(connfd, &msg_id, sizeof(msg_id));
        if (msg_id == DEVICE_CERT_MSG_ID) {
            printf("Get device cert.\n");
            unsigned char dev_cert[MAX] = {};
            size_t dev_cert_len = MAX;
            ret = get_dev_cert(ctx, dev_cert, &dev_cert_len);
            if (ret != TSI_SUCCESS) {
                printf("Failed to get TSI version.\n");
                return ret;
            }
            write(connfd, dev_cert, dev_cert_len);
        } else if (msg_id == ATTEST_MSG_ID) {
            printf("Get attestation token.\n");
            unsigned char challenge[CHALLENGE_SIZE] = {};
            read(connfd, challenge, CHALLENGE_SIZE);
            unsigned char token[MAX] = {};
            size_t token_len = MAX;
            ret = get_attestation_token(ctx, challenge, CHALLENGE_SIZE, token, &token_len);
            if (ret != TSI_SUCCESS) {
                printf("Failed to get attestation token.\n");
                return ret;
            }
            write(connfd, token, token_len);
        } else if (msg_id == VERIFY_SUCCESS_MSG_ID) {
            printf("verify success!\n");
            ret = VERIFY_SUCCESS;
            break;
        } else if (msg_id == VERIFY_FAILED_MSG_ID) {
            printf("verify failed!\n");
            ret = VERIFY_FAILED;
            break;
        } else {
            ret = VERIFY_FAILED;
            break;
        }
    }

    return ret;
}

void print_usage(char *name)
{
    printf("Usage: %s [options]\n", name);
    printf("Options:\n");
    printf("-i, --ip <ip>                    ip\n");
    printf("-p, --port <port>                port\n");
    printf("-h, --help                       Print Help (this message) and exit\n");
}

int main(int argc, char *argv[])
{
    int ret = 1;
    int sockfd, connfd, len;
    struct sockaddr_in servaddr, cli;
    int ip = htonl(INADDR_LOOPBACK);
    int port = htons(PORT);

    int option;
    struct option const long_options[] = {
        { "ip", required_argument, NULL, 'i' },
        { "port", required_argument, NULL, 'p' },
        { "help", no_argument, NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };
    while (1) {
        int option_index = 0;
        option = getopt_long(argc, argv, "i:p:h", long_options, &option_index);
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
        case 'h':
            print_usage(argv[0]);
        default:
            fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
            exit(1);
        }
    }

    tsi_ctx *ctx = tsi_new_ctx();
    if (ctx == NULL) {
        return 1;
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("socket creation failed...\n");
        goto end;
    }
    else
        printf("Socket successfully created..\n");
    bzero(&servaddr, sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = ip;
    servaddr.sin_port = port;

    if ((bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr))) != 0) {
        printf("socket bind failed...\n");
        goto end;
    }
    else
        printf("Socket successfully binded..\n");

    if ((listen(sockfd, 5)) != 0) {
        printf("Listen failed...\n");
        goto end;
    }
    else
        printf("Server listening..\n");
    len = sizeof(cli);

    connfd = accept(sockfd, (struct sockaddr *)&cli, &len);
    if (connfd < 0) {
        printf("server accept failed...\n");
        goto end;
    }
    else
        printf("server accept the client...\n");

    ret = handle_connect(connfd, ctx);

    close(sockfd);

end:
    tsi_free_ctx(ctx);
    return ret;
}
