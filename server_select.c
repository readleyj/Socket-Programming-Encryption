#include "helpers.h"

int main(int argc, char *argv[])
{
    fd_set master;
    fd_set read_fds;
    int fdmax, listener, newfd;
    int opt, status, i, connection_status, yes = 1;
    char *PORT;
    struct sockaddr_storage remote_addr;
    socklen_t addrlen;

    struct addrinfo hints = {
            .ai_family = AF_UNSPEC,
            .ai_socktype = SOCK_STREAM,
            .ai_flags = AI_PASSIVE
    }, *servinfo, *res;

    packet pack = create_packet();
    unsigned char *data_buffer = malloc(MAX_DATA_SIZE);

    FD_ZERO(&master);
    FD_ZERO(&read_fds);

    while ((opt = getopt(argc, argv, "p:")) != -1) {
        if (opt == 'p') {
            PORT = optarg;
            break;
        }
    }

    if ((status = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0)
    {
        exit(1);
    }

    for(res = servinfo; res != NULL; res = res->ai_next) {
        listener = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

        if (listener < 0) {
            continue;
        }

        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

        if (bind(listener, res->ai_addr, res->ai_addrlen) < 0) {
            close(listener);
            continue;
        }

        break;
        }

    if (res == NULL)
    {
        fprintf(stderr, "selectserver: failed to bind\n");
        exit(2);
    }

    freeaddrinfo(servinfo);

    if (listen(listener, BACKLOG) == -1)
    {
        perror("listen");
        exit(3);
    }

    FD_SET(listener, &master);
    fdmax = listener;

    while (1)
    {
        read_fds = master;

        if (select(fdmax + 1, &read_fds, NULL, NULL, NULL) == -1)
        {
            exit(4);
        }

        for (i = 0; i <= fdmax; i++)
        {
            if (FD_ISSET(i, &read_fds))
            {
                if (i == listener)
                {
                    addrlen = sizeof(remote_addr);
                    newfd = accept(listener, (struct sockaddr *)&remote_addr, &addrlen);

                    if (newfd == -1)
                    {
                        perror("accept");
                    } else
                    {
                        FD_SET(newfd, &master);

                        if (newfd > fdmax) {
                            fdmax = newfd;
                        }
                    }
                } else
                {
                    while (1) {
                        ssize_t received = recv_data(i, data_buffer, HEADER_SIZE);

                        if (received <= 0) {
                            close(i);
                            FD_CLR(i, &master);
                            break;
                        } else {
                            decode_header(data_buffer, &pack);
                            uint64_t packet_length = be64toh(pack.head->length);

                            if (check_protocol_violations(&pack) == -1) {
                                close(i);
                                FD_CLR(i, &master);
                                break;
                            }

                            connection_status = recv_data(i, data_buffer + HEADER_SIZE, packet_length - HEADER_SIZE);

                            if (connection_status == 0) {
                                close(i);
                                FD_CLR(i, &master);
                                break;
                            }
                            else if (connection_status == -1) {
                                close(i);
                                FD_CLR(i, &master);
                                break;
                            }

                            if (calc_checksum(data_buffer, packet_length) != 0) {
                                close(i);
                                FD_CLR(i, &master);
                                break;
                            }

                            decode_packet(data_buffer, &pack);
                            vigenere_cipher(pack.data, pack.head->keyword, htons(pack.head->op),
                                            packet_length - HEADER_SIZE);

                            pack.head->checksum = 0;
                            encode_packet(data_buffer, &pack);

                            uint16_t checksum = calc_checksum(data_buffer, packet_length);
                            memcpy(data_buffer + OP_SIZE, (unsigned char *) &checksum, CHECKSUM_SIZE);

                            if (send_data(i, data_buffer, packet_length)) {
                                perror("sendall");
                            }
                        }
                    }
                }
            }
        }
    }

    return 0;
}