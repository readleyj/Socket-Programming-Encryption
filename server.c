#include "helpers.h"

int main(int argc, char *argv[])
{
    int opt, status, yes = 1;
    int sockfd, con_fd;
    char *PORT;
    struct sigaction sa;
    struct sockaddr_storage remote_addr;
    socklen_t sin_size;

    struct addrinfo hints = {
            .ai_family = AF_UNSPEC,
            .ai_socktype = SOCK_STREAM,
            .ai_flags = AI_PASSIVE
    }, *servinfo, *res;

    while((opt = getopt(argc, argv, "p:")) != -1)
    {
        if (opt == 'p')
        {
            PORT = optarg;
            break;
        }
    }

    if ((status = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0)
    {
        return 1;
    }

    for (res = servinfo; res != NULL; res = res->ai_next)
    {
        if ((sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) == -1)
        {
            perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
        {
            perror("setsockopt");
            exit(1);
        }

        if (bind(sockfd, res->ai_addr, res->ai_addrlen) == -1)
        {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo);

    if (res == NULL)
    {
        fprintf(stderr, "server: failed to bind\n");
        exit(1);
    }

    if (listen(sockfd, BACKLOG) == -1)
    {
        perror("listen");
        exit(1);
    }

    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

    if (sigaction(SIGCHLD, &sa, NULL) == -1)
    {
        perror("sigaction");
        exit(1);
    }

    while(1)
    {
        sin_size = sizeof(remote_addr);
        con_fd = accept(sockfd, (struct sockaddr *)&remote_addr, &sin_size);

        if (con_fd == -1)
        {
            perror("accept");
            exit(1);
        }

        if (!fork()) {
            packet pack = create_packet();
            unsigned char *data_buffer = malloc(MAX_DATA_SIZE);

            while (1) {
                ssize_t received = recv_data(con_fd, data_buffer, HEADER_SIZE);

                if (received == 0) {
                    perror("Connection closed");
                    break;
                }

                decode_header(data_buffer, &pack);
                uint64_t packet_length = be64toh(pack.head->length);

                if (check_protocol_violations(&pack) == -1) {
                    break;
                }

                received = recv_data(con_fd, data_buffer + HEADER_SIZE, packet_length - HEADER_SIZE);

                if (received == 0) {
                    perror("Connection closed");
                    break;
                } else if (received == -1) {
                    perror("Can't receive anything");
                    break;
                }

                if (calc_checksum(data_buffer, packet_length) != 0) {
                    break;
                }

                decode_packet(data_buffer, &pack);
                vigenere_cipher(pack.data, pack.head->keyword, htons(pack.head->op), packet_length - HEADER_SIZE);

                pack.head->checksum = 0;
                encode_packet(data_buffer, &pack);

                uint16_t checksum = calc_checksum(data_buffer, packet_length);
                memcpy(data_buffer + OP_SIZE, (unsigned char *) &checksum, CHECKSUM_SIZE);

                if (send_data(con_fd, data_buffer, packet_length) == - 1) {
                    perror("sendall");
                }

            }
            free(data_buffer);
            close(con_fd);
            exit(1);
        }
        close(con_fd);
    }
}