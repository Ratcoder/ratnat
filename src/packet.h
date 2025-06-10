#ifndef SHARED_H
#define SHARED_H


#include <stdint.h>
#include <sodium.h>


#define MSG_SERVICE 0
#define MSG_CONNECTION_REQUEST 1
#define MSG_CONNECTION_ACCEPTED 2
#define MSG_PING_REQUEST 3
#define MSG_PING_RESPONCE 4
#define TUNNEL_FLAG 0
#define CLIENT_FLAG 1
#define KEY_SIZE crypto_aead_chacha20poly1305_ietf_KEYBYTES
#define PACKET_DATA_SIZE 1<<16
#define SERVICE_PACKET_HEADER_SIZE 13
#define GENERIC_PACKET_HEADER_SIZE 9


// Packet of service traffic
struct service_packet
{
    uint8_t type; // Always MSG_SERVICE
    uint64_t nonce;
    uint32_t connection_id;
    uint8_t data[PACKET_DATA_SIZE];
} __attribute__((packed));

struct connection_request_packet
{
    uint8_t type; // Always MSG_CONNECTION_REQUEST
    uint64_t nonce;
    uint8_t session_key[32];
} __attribute__((packed));

struct connection_accepted_packet
{
    uint8_t type; // Always MSG_CONNECTION_ACCEPTED
} __attribute__((packed));

// Structure common to all packets
struct generic_packet
{
    uint8_t type;
    uint64_t nonce;
    uint8_t data[PACKET_DATA_SIZE];
} __attribute__((packed));


// Prints the octets in data in a side by side hex and ascii view.
void print_hex(uint8_t *data, int len);
int encrypt_packet(struct generic_packet *packet, int packet_len,
    uint8_t sender_flag, uint8_t *key, uint64_t nonce);
int decrypt_packet(struct generic_packet *packet, int packet_len, uint8_t sender_flag, uint8_t *key);


#endif