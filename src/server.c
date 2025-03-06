#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <time.h>
#include <stdint.h>
#include "packet.h"
#include "config.h"
#include <poll.h>
#include <sodium.h>


#define BUFFER_SIZE 1<<16
#define MAX_CONNECTIONS 100
#define MAX_CONNECTION_INACTIVITY 60


struct connection {
    int id;
    time_t last_activity;
    struct sockaddr_in addr;
};


int server(char *config_file)
{
    struct config config;
    read_config(config_file, &config);

    // Define the Minecraft server address
    struct sockaddr_in minecraft_addr;
    minecraft_addr.sin_family = AF_INET;
    minecraft_addr.sin_port = htons(config.external_port);
    minecraft_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    // Define the tunnel address
    struct sockaddr_in tunnel_addr;
    tunnel_addr.sin_family = AF_INET;
    tunnel_addr.sin_port = htons(config.tunnel_port);
    tunnel_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    // Create a socket for accepting packets from the Minecraft clients
    int minecraft_socket = socket(AF_INET, SOCK_DGRAM, 0);
    bind(minecraft_socket, (struct sockaddr *) &minecraft_addr, sizeof(minecraft_addr));
    fcntl(minecraft_socket, F_SETFL, O_NONBLOCK);

    // Create the tunnel socket
    int tunnel_socket = socket(AF_INET, SOCK_DGRAM, 0);
    socklen_t address_len = sizeof(struct sockaddr_in);
    bind(tunnel_socket, (struct sockaddr *) &tunnel_addr, sizeof(tunnel_addr));
    fcntl(tunnel_socket, F_SETFL, O_NONBLOCK);

    // State for minecraft connections
    struct connection connections[MAX_CONNECTIONS];
    int num_connections = 0;
    int connection_id_counter = 0;
    struct packet packet;

    // State for tunnel connection
    int is_authenticated = 0;
    uint8_t auth_challenge[64];
    uint64_t message_nonce_counter = 4;
    uint8_t session_key[32];

    printf("Tunnel listening on port %d\n", config.tunnel_port);

    for (;;)
    {
        // Wait until a packet is available
        struct pollfd poll_fds[2];
        poll_fds[0].fd = tunnel_socket;
        poll_fds[0].events = POLLIN;
        poll_fds[1].fd = minecraft_socket;
        poll_fds[1].events = POLLIN;
        poll(poll_fds, 2, -1);

        if (!is_authenticated)
        {
            char buffer[PACKET_DATA_SIZE];
            struct encrypted_packet *auth_packet = (struct encrypted_packet *) (buffer + 8);
            int data_len = recvfrom(tunnel_socket, buffer, BUFFER_SIZE, 0, (struct sockaddr *) &tunnel_addr, &address_len);
            
            if (data_len != 8 * 2 + 32 + crypto_aead_chacha20poly1305_IETF_ABYTES) continue;
            if (*(uint64_t *) buffer != CONNECTION_REQUEST) continue;

            int packet_len = decrypt_packet(config.secret_key, CLIENT_FLAG, auth_packet, data_len - 8);
            if (packet_len != 32 + ENCRYPTED_PACKET_HEADER_SIZE) continue;

            printf("Client connected\n");
            is_authenticated = 1;
            memcpy(session_key, auth_packet->data, 32);

            uint64_t connection_accepted = CONNECTION_ACCEPTED;
            sendto(tunnel_socket, &connection_accepted, sizeof(uint64_t), 0, (struct sockaddr *) &tunnel_addr, address_len);

            continue;
        }

        struct sockaddr_in recv_addr;
        socklen_t recv_addr_len = sizeof(recv_addr);
        
        // Receive a packet from the tunnel client
        int data_len = recvfrom(tunnel_socket, packet.data, BUFFER_SIZE, 0, (struct sockaddr *) &recv_addr, &recv_addr_len);
        if (data_len == -1) goto recv_from_minecraft;

        // Reject all packets not from the tunnel client
        if (recv_addr.sin_addr.s_addr != tunnel_addr.sin_addr.s_addr || recv_addr.sin_port != tunnel_addr.sin_port)
        {
            printf("Received packet from unknown source.\n");
            continue;
        }
        
        // Decrypt the packet
        int packet_len = decrypt_packet(session_key, CLIENT_FLAG, (struct encrypted_packet *) &packet, data_len);
        if (packet_len == -1) {
            printf("Decryption failed\n");
            continue; // Forgery detected, ignore the packet
        }

        // Find the connection
        for (int i = 0; i < num_connections; i++)
        {
            if (connections[i].id == packet.connection_id)
            {
                #ifdef TRACE
                printf("To minecraft client: message %d of len %d\n", recv_message_counter, buffer_len - 8);
                print_hex(buffer + 8, buffer_len - 8);
                #endif
                
                // Forward the packet to the minecraft client, skipping the first 4 bytes (connection ID)
                sendto(minecraft_socket, packet.data, packet_len, 0, (struct sockaddr *) &connections[i].addr, sizeof(connections[i].addr));
                break;
            }
        }

        recv_from_minecraft:;

        // Receive packets from the minecraft clients
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        data_len = recvfrom(minecraft_socket, packet.data, BUFFER_SIZE, 0, (struct sockaddr *) &client_addr, &client_addr_len);
        if (data_len == -1) continue;

        // Find the connection
        int connection_found = 0;
        int connection_index;
        for (int i = 0; i < num_connections; i++)
        {
            if (connections[i].addr.sin_addr.s_addr == client_addr.sin_addr.s_addr && connections[i].addr.sin_port == client_addr.sin_port)
            {
                connection_found = 1;
                connection_index = i;
                break;
            }
        }

        // If the connection does not exist, create it
        if (!connection_found)
        {
            if (num_connections == MAX_CONNECTIONS)
            {
                // Too many connections, try to replace an inactive one
                time_t current_time = time(NULL);
                for (int i = 0; i < num_connections; i++)
                {
                    if (current_time - connections[i].last_activity > MAX_CONNECTION_INACTIVITY)
                    {
                        connections[i] = connections[num_connections - 1];
                        num_connections--;
                        break;
                    }
                }

                // If there is no connection to replace, print an error and ignore the packet
                if (num_connections == MAX_CONNECTIONS)
                {
                    printf("Too many connections\n");
                    continue;
                }
            }

            printf("Created new connection with ID %d\n", num_connections);
            connections[num_connections].id = connection_id_counter++;
            connections[num_connections].addr = client_addr;
            num_connections++;
            connection_index = num_connections - 1;
        }

        // Update the last activity time
        connections[connection_index].last_activity = time(NULL);

        packet.connection_id = connections[connection_index].id;

        // Encrypt the packet
        message_nonce_counter++;
        packet_len = encrypt_packet(session_key, message_nonce_counter, TUNNEL_FLAG, (struct encrypted_packet *) &packet, data_len);
        sendto(tunnel_socket, &packet, packet_len, 0, (struct sockaddr *) &tunnel_addr, sizeof(tunnel_addr));
    }
}