///////////////////////////////////////////////////////////////////
// Author: Pierce Gray
// File Name: shared.c
// Purpose: Contains the shared functions and constants for used
//          in both the client and tunnel programs.
///////////////////////////////////////////////////////////////////


#include "packet.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sodium.h>


int encrypt_packet(uint8_t *key, uint64_t nonce, uint8_t sender_flag, struct encrypted_packet *packet, int data_len)
{
    uint8_t nonce_bytes[12];
    memcpy(nonce_bytes, &nonce, 8);
    nonce_bytes[8] = sender_flag;
    memset(nonce_bytes + 9, 0, 3);
    unsigned long long ciphertext_length;

    int result = crypto_aead_chacha20poly1305_ietf_encrypt(packet->data, &ciphertext_length, packet->data, data_len + PACKET_HEADER_SIZE - ENCRYPTED_PACKET_HEADER_SIZE, NULL, 0, NULL, nonce_bytes, key);
    packet->nonce = nonce;
    return ciphertext_length + ENCRYPTED_PACKET_HEADER_SIZE;
}

int decrypt_packet(uint8_t *key, uint8_t sender_flag, struct encrypted_packet *packet, int packet_len)
{
    if (packet_len < ENCRYPTED_PACKET_HEADER_SIZE) return -1;

    // First 8 bytes of the nonce are the nonce, the 9th byte is the sender flag
    uint8_t nonce_bytes[12];
    memcpy(nonce_bytes, &packet->nonce, 8);
    nonce_bytes[8] = sender_flag;
    memset(nonce_bytes + 9, 0, 3);

    unsigned long long plaintext_len;

    int result = crypto_aead_chacha20poly1305_ietf_decrypt(packet->data, &plaintext_len, NULL, packet->data, packet_len - ENCRYPTED_PACKET_HEADER_SIZE, NULL, 0, nonce_bytes, key);
    if (result != 0) return -1;
    return plaintext_len + ENCRYPTED_PACKET_HEADER_SIZE;
}

void print_hex(uint8_t *data, int len)
{
    for (int i = 0; i < len; i += 16)
    {
        printf("%03d ", i);
        int num_bytes = len - i < 16 ? len - i : 16;
        for (int j = i; j < i + num_bytes; j++) printf(" %02x", data[j]);

        printf("  ");
        // Pad the last line with spaces if necessary
        for (int j = 0; j < 16 - num_bytes; j++) printf("   ");

        for (int j = i; j < i + num_bytes; j++)
        {
            if (data[j] >= 32 && data[j] <= 126) printf("%c", data[j]);
            else printf(".");
        }

        printf("\n");
    }
    printf("\n");
}

