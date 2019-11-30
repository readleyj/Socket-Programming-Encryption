#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <unistd.h>
#include <ctype.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <errno.h>

#define MAX_DATA_SIZE 10000000
#define HEADER_SIZE 16
#define BACKLOG 10
#define LOWERCASE_END 122
#define LOWERCASE_BEGIN 97
#define NUMALPHA 26

#define OP_SIZE 2
#define CHECKSUM_SIZE 2
#define KEYWORD_SIZE 4
#define LENGTH_SIZE 8

typedef struct
{
    uint16_t op;
    uint16_t checksum;
    char keyword[4];
    uint64_t length;
} header;

typedef struct
{
    header *head;
    unsigned char* data;
} packet;

packet create_packet();
void encode_packet (unsigned char* buffer, packet *p);
void decode_packet(unsigned char *buffer, packet *p);
void convert_string_to_lower(unsigned char* str);
void left_rotate_by_one(unsigned char* arr, int size);
void left_rotate(unsigned char* arr, int offset, int size);
void vigenere_cipher(unsigned char * text, const char keyword[4], uint16_t op, size_t msg_len);
void decode_header(unsigned char *buffer, packet *p);
void sigchld_handler(int s);
unsigned short calc_checksum(const unsigned char *buf, unsigned size);
int send_data(int socket, unsigned char *buffer, size_t len);
int recv_data(int socket, unsigned char *buffer, size_t len);
int check_protocol_violations(packet *p);
size_t read_stdin(unsigned char *message, int read_size);



