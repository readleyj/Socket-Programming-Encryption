#include "helpers.h"

packet create_packet()
{
    header head =
            {
                    .op = 0,
                    .checksum = 0,
                    .keyword = "",
                    .length = 0,
            };

    packet pack =
            {
                    .head = &head,
                    .data = NULL
            };

    pack.head = malloc(sizeof(header));
    pack.data = malloc(MAX_DATA_SIZE - HEADER_SIZE);
    return pack;
}

void encode_packet (unsigned char* buffer, packet *p)
{
    header *head = p->head;
    memcpy(buffer, (unsigned char *) &(head->op), OP_SIZE);
    memcpy(buffer + OP_SIZE, (unsigned char *) &(head->checksum), CHECKSUM_SIZE);
    memcpy(buffer + CHECKSUM_SIZE + OP_SIZE, head->keyword, KEYWORD_SIZE);
    memcpy(buffer + CHECKSUM_SIZE + OP_SIZE + KEYWORD_SIZE, (unsigned char *) &(head->length), LENGTH_SIZE);
    memcpy(buffer + CHECKSUM_SIZE + OP_SIZE + KEYWORD_SIZE + LENGTH_SIZE, p->data, be64toh(head->length) - HEADER_SIZE);
}

    void decode_packet(unsigned char *buffer, packet *p) {
    header *head = p->head;
    uint64_t packet_length = be64toh(head->length);
    memcpy(p->data, buffer + CHECKSUM_SIZE + OP_SIZE + KEYWORD_SIZE + LENGTH_SIZE, packet_length);
}

void decode_header(unsigned char *buffer, packet *p)
{
    header *head = p->head;
    memcpy(&(head->op), buffer, OP_SIZE);
    memcpy(&(head->checksum), buffer + OP_SIZE, CHECKSUM_SIZE);
    memcpy(head->keyword, buffer + OP_SIZE + CHECKSUM_SIZE, KEYWORD_SIZE);
    memcpy(&(head->length), buffer + OP_SIZE + CHECKSUM_SIZE + KEYWORD_SIZE, LENGTH_SIZE);
}

// Code adapted from https://gist.github.com/moogzy/8466a94fb1c2c45593b04e97367dbb9e

void vigenere_cipher(unsigned char * text, const char keyword[4], uint16_t op, size_t msg_len)
{
    int plain_val, cipher_val, subkey_val, key_val;
    int op_type = (op == 0) ? 1 : -1;
    size_t i, j = 0;

    for (i = 0; i < msg_len; i++)
    {
        j = j % 4;
        text[i] = (unsigned char) tolower(text[i]);
        plain_val = (int) text[i];
        key_val = (int) (keyword[j]) - 'a';
        cipher_val = plain_val + op_type * key_val;
        subkey_val = NUMALPHA - key_val;

        if (isalpha(text[i]))
        {
            if (cipher_val > LOWERCASE_END || cipher_val < LOWERCASE_BEGIN)
            {
                cipher_val = plain_val - op_type * subkey_val;
            }

            else
            {
                cipher_val = plain_val + op_type * key_val;
            }
            j++;
        }

        else
        {
            cipher_val = plain_val;
        }

        text[i] = (unsigned char) cipher_val;
    }
}

size_t read_stdin(unsigned char *message, int read_size)
{
    size_t bytes_read;
    size_t total_read = 0;

    while (bytes_read = read(STDIN_FILENO, message + total_read, read_size), bytes_read != 0) {

        if (bytes_read == -1) {
            perror("read");
            exit(EXIT_FAILURE);
        }

        total_read += bytes_read;

        if (total_read == read_size) break;
    }

    return total_read;
}

int check_protocol_violations(packet *p)
{
    int error = 0;
    header *head = p->head;
    uint16_t op = ntohs(head->op);
    uint64_t packet_length = be64toh(head->length);

    if (op > 1) error = -1;
    else if (packet_length > MAX_DATA_SIZE) error = -1;

    return error;
}

void convert_string_to_lower(unsigned char* str)
{
    for (int i = 0; str[i]; i++)
    {
        str[i] = (char) tolower(str[i]);
    }
}

// Retrieved from https://www.geeksforgeeks.org/array-rotation/

void left_rotate_by_one(unsigned char* arr, int size)
{
    int i;
    unsigned char temp = arr[0];

    for (i = 0; i < size - 1; i++)
        arr[i] = arr[i + 1];

    arr[i] = temp;
}

void left_rotate(unsigned char* arr, int offset, int size)
{
    int i;
    for (i = 0; i < offset; i++)
        left_rotate_by_one(arr, size);
}

// Retrieved from http://locklessinc.com/articles/tcp_checksum/

unsigned short calc_checksum(const unsigned char *buf, unsigned size)
{
    unsigned long long sum = 0;
    const unsigned long long *b = (unsigned long long *) buf;

    unsigned t1, t2;
    unsigned short t3, t4;

    while (size >= sizeof(unsigned long long))
    {
        unsigned long long s = *b++;
        sum += s;
        if (sum < s) sum++;
        size -= 8;
    }

    buf = (const unsigned char *) b;
    if (size & 4u)
    {
        unsigned s = *(unsigned *)buf;
        sum += s;
        if (sum < s) sum++;
        buf += 4;
    }

    if (size & 2u)
    {
        unsigned short s = *(unsigned short *) buf;
        sum += s;
        if (sum < s) sum++;
        buf += 2;
    }

    if (size)
    {
        unsigned char s = *(unsigned char *) buf;
        sum += s;
        if (sum < s) sum++;
    }

    t1 = sum;
    t2 = sum >> 32u;
    t1 += t2;
    if (t1 < t2) t1++;
    t3 = t1;
    t4 = t1 >> 16u;
    t3 += t4;
    if (t3 < t4) t3++;

    return ~t3;
}

// Code adapted from Beej's Guide to Network Programming on Page 41

int send_data(int socket, unsigned char *buffer, size_t len)
{
    size_t total_sent = 0;
    size_t bytes_left = len;
    size_t n;

    while (total_sent < len)
    {
        n = send(socket, buffer + total_sent, bytes_left, 0);

        if (n == -1) return n;

        total_sent += n;
        bytes_left -= n;

    }

    return total_sent;
}

int recv_data(int socket, unsigned char *buffer, size_t len)
{
    size_t total_received = 0;
    size_t bytes_left = len;
    size_t n;

    while (total_received < len)
    {
        n = recv(socket, buffer + total_received, bytes_left, 0);

        if (n == -1 || n == 0)
        {
            return n;
        }

        total_received += n;
        bytes_left -= n;
    }
    return total_received;
}

// Code adapted from Beej's Guide to Network Programming

void sigchld_handler(int s)
{
    int saved_errno = errno;

    while (waitpid(-1, NULL, WNOHANG) > 0);

    errno = saved_errno;
}
