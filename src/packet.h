#ifndef SHARED_H
#define SHARED_H


#include <stdint.h>
#include <sodium.h>


#define CONNECTION_REQUEST 1
#define CONNECTION_RESPONCE 2
#define TUNNEL_FLAG 0
#define CLIENT_FLAG 1
#define KEY_SIZE crypto_aead_chacha20poly1305_ietf_KEYBYTES
#define PACKET_DATA_SIZE 1<<16
#define PACKET_HEADER_SIZE 12
#define ENCRYPTED_PACKET_HEADER_SIZE 8


struct packet
{
    uint64_t nonce;
    uint32_t connection_id;
    uint8_t data[PACKET_DATA_SIZE];
} __attribute__((packed));

struct encrypted_packet
{
    uint64_t nonce;
    uint8_t data[PACKET_DATA_SIZE];
} __attribute__((packed));


// Prints the octets in data in a side by side hex and ascii view.
void print_hex(uint8_t *data, int len);
int decrypt_packet(uint8_t *key, uint8_t sender_flag, struct encrypted_packet *packet, int packet_len);
int encrypt_packet(uint8_t *key, uint64_t nonce, uint8_t sender_flag, struct encrypted_packet *packet, int data_len);

#endif