#include "helpers.h"

int main(int argc, char *argv[]) {

    int opt, sockfd, OP_TYPE;
    char *HOST_ADDRESS, *PORT, KEYWORD[4];
    unsigned char *message = malloc(MAX_DATA_SIZE - HEADER_SIZE);
    unsigned char *data_buffer = malloc(MAX_DATA_SIZE);

    struct addrinfo hints = {
            .ai_family = AF_UNSPEC,
            .ai_socktype = SOCK_STREAM
    }, *servinfo, *res;

    while ((opt = getopt(argc, argv, "h:p:o:k:")) != -1) {
        switch (opt) {
            case 'h': {
                HOST_ADDRESS = optarg;
                break;
            }
            case 'p': {
                PORT = optarg;
                break;
            }
            case 'o': {
                OP_TYPE = (int) strtol(optarg, NULL, 10);
                break;
            }
            case 'k': {
                convert_string_to_lower(optarg);
                strcpy(KEYWORD, optarg);
                break;
            }
        }
    }

    if (getaddrinfo(HOST_ADDRESS, PORT, &hints, &servinfo) != 0) {
        return 1;
    }

    for (res = servinfo; res != NULL; res = res->ai_next) {
        if ((sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) == -1) {
            perror("client: socket");
            continue;
        }

        if (connect(sockfd, res->ai_addr, res->ai_addrlen) == -1) {
            close(sockfd);
            perror("client: connect");
            continue;
        }

        break;
    }

    if (res == NULL) {
        return 2;
    }

    freeaddrinfo(servinfo);
    packet pack = create_packet();

    while (1)
        {
            size_t keyword_offset, packet_length, total_read = 0, num_alphabetic = 0;
            ssize_t received;

            total_read = read_stdin(message, MAX_DATA_SIZE - HEADER_SIZE);
            packet_length = total_read + HEADER_SIZE;

            for (size_t i = 0; i <= total_read; i++) {
                if (isalpha(message[i])) {
                    num_alphabetic++;
                }
            }

            pack.head->op = htons(OP_TYPE);
            pack.head->checksum = 0;
            strcpy(pack.head->keyword, KEYWORD);
            pack.head->length = htobe64(packet_length);
            pack.data = message;

            encode_packet(data_buffer, &pack);
            uint16_t checksum = calc_checksum(data_buffer, packet_length);
            memcpy(data_buffer + OP_SIZE, (unsigned char *) &checksum, CHECKSUM_SIZE);

            if (send_data(sockfd, data_buffer, packet_length) == - 1)
            {
                perror("sendall");
                exit(1);
            }

            memset(data_buffer, 0, MAX_DATA_SIZE);

            recv_data(sockfd, data_buffer, HEADER_SIZE);
            decode_header(data_buffer, &pack);
            packet_length = be64toh(pack.head->length);

            if (check_protocol_violations(&pack) == -1)
            {
                exit(1);
            }

            received = recv_data(sockfd, data_buffer + HEADER_SIZE, packet_length - HEADER_SIZE);

            if (received == 0) {
                perror("Connection closed");
                exit(1);
            } else if (received == -1) {
                perror("Can't receive anything");
                exit(1);
            }

            decode_packet(data_buffer, &pack);

            if (calc_checksum(data_buffer, packet_length) != 0)
            {
                exit(1);
            }

            printf("%s", pack.data);

            if (total_read < MAX_DATA_SIZE - HEADER_SIZE)
            {
                break;
            }

            keyword_offset = num_alphabetic % KEYWORD_SIZE;
            left_rotate(KEYWORD, keyword_offset, KEYWORD_SIZE);
        }

        close(sockfd);
    }
