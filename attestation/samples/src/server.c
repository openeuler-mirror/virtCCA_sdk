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

static int deal_cmd(int connfd, tsi_ctx *ctx, enum MSG_ID msg_id)
{
    int ret = -1;
    unsigned char buff[MAX] = {0};
    size_t len = MAX;

    switch (msg_id) {
        case DEVICE_CERT_MSG_ID:
            printf("Get device cert.\n");
            ret = get_dev_cert(ctx, buff, &len);
            if (ret != TSI_SUCCESS) {
                printf("Failed to get TSI version.\n");
                return ret;
            }
            break;
        case ATTEST_MSG_ID:
            printf("Get attestation token.\n");
            unsigned char challenge[CHALLENGE_SIZE] = {};
            if (read(connfd, challenge, CHALLENGE_SIZE) != CHALLENGE_SIZE) {
                printf("read challenge failed\n");
                return -1;
            }
            ret = get_attestation_token(ctx, challenge, CHALLENGE_SIZE, buff, &len);
            if (ret != TSI_SUCCESS) {
                printf("Failed to get attestation token.\n");
                return ret;
            }
            break;
        case VERIFY_SUCCESS_MSG_ID:
            printf("Succeed to verify!\n");
            return VERIFY_SUCCESS;
        case VERIFY_FAILED_MSG_ID:
            printf("Failed to verify!\n");
            return VERIFY_FAILED;
        default:
            printf("not supported cmd %u\n", msg_id);
            return -1;
    }

    if (write(connfd, buff, len) != len) {
        printf("send dev cert failed\n");
        return -1;
    }
    return VERIFY_CONTINUE;
}

static int handle_connect(int connfd, tsi_ctx *ctx)
{
    int ret;
    enum MSG_ID msg_id;
    int major, minor;

    ret = get_version(ctx, &major, &minor);
    if (ret != TSI_SUCCESS) {
        printf("Failed to get TSI version.\n");
        return ret;
    }
    printf("TSI version %d.%d advertised\n", major, minor);

    for (;;) {
        if (read(connfd, &msg_id, sizeof(msg_id)) != sizeof(msg_id)) {
            printf("read msg id failed\n");
            return -1;
        }

        ret = deal_cmd(connfd, ctx, msg_id);
        if (ret == VERIFY_CONTINUE) {
            continue;
        } else if (ret == VERIFY_SUCCESS) {
            return 0;
        } else {
            break;
        }
    }

    return ret;
}

static void print_usage(char *name)
{
    printf("Usage: %s [options]\n", name);
    printf("Options:\n");
    printf("\t-i, --ip <ip>                      Listening IP address\n");
    printf("\t-p, --port <port>                  Listening tcp port\n");
    printf("\t-h, --help                         Print Help (this message) and exit\n");
}

static int parse_args(int argc, char *argv[], server_args *args)
{
    int option;
    int option_index = 0;
    args->ip =  htonl(INADDR_LOOPBACK);
    args->port = htons(PORT);

    struct option const long_options[] = {
        { "ip", required_argument, NULL, 'i' },
        { "port", required_argument, NULL, 'p' },
        { "help", no_argument, NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };
    while ((option = getopt_long(argc, argv, "i:p:h", long_options, &option_index)) != -1) {
        switch (option) {
            case 'i':
                args->ip = inet_addr(optarg);
                break;
            case 'p':
                args->port = htons(atoi(optarg));
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
    int sockfd = -1, connfd = -1, len;
    struct sockaddr_in servaddr, cli;
    server_args args = {0};

    if (parse_args(argc, argv, &args)) {
        return -1;
    }

    tsi_ctx *ctx = tsi_new_ctx();
    if (ctx == NULL) {
        return 1;
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("socket creation failed...\n");
        goto end;
    } else {
        printf("Socket successfully created..\n");
    }
    bzero(&servaddr, sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = args.ip;
    servaddr.sin_port = args.port;

    if ((bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr))) != 0) {
        printf("socket bind failed...\n");
        goto end;
    } else {
        printf("Socket successfully binded..\n");
    }

    if ((listen(sockfd, 5)) != 0) {
        printf("Listen failed...\n");
        goto end;
    } else {
        printf("Server listening..\n");
    }
    len = sizeof(cli);

    connfd = accept(sockfd, (struct sockaddr *)&cli, &len);
    if (connfd < 0) {
        printf("server accept failed...\n");
        goto end;
    } else {
        printf("server accept the client...\n");
    }

    ret = handle_connect(connfd, ctx);

end:
    close(sockfd);
    close(connfd);
    tsi_free_ctx(ctx);
    return ret;
}
