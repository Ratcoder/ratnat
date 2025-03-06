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
    int socket;
    time_t last_activity;
    struct sockaddr_in addr;
};


int client(char *config_file)
{
    struct config config;
    read_config(config_file, &config);

    // Define the Minecraft server address
    struct sockaddr_in minecraft_addr;
    minecraft_addr.sin_family = AF_INET;
    minecraft_addr.sin_port = htons(config.internal_port);
    minecraft_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Define the tunnel address
    struct sockaddr_in tunnel_addr;
    tunnel_addr.sin_family = AF_INET;
    tunnel_addr.sin_port = htons(config.tunnel_port);
    tunnel_addr.sin_addr.s_addr = config.tunnel_ip;

    // Create the tunnel socket
    int tunnel_socket = socket(AF_INET, SOCK_DGRAM, 0);

    struct connection connections[MAX_CONNECTIONS];
    for (int i = 0; i < MAX_CONNECTIONS; i++) connections[i].socket = -1;
    int num_connections = 0;
    struct packet packet;
    uint64_t message_nonce_counter = 100;

    // Generate a session key
    uint8_t session_key[32];
    randombytes_buf(session_key, 32);

    uint64_t connection_request_nonce = time(NULL);

    // Connection request is: CONNECTION_REQUEST (u64) | PACKET (NONCE (u64) | SESSION_KEY (32b) | tag (16b))
    char con_req_bytes[8 * 2 + 32 + 16];
    *(uint64_t *) con_req_bytes = CONNECTION_REQUEST;
    struct packet *con_req = (struct packet *) (con_req_bytes + 8);
    memcpy(con_req->data, session_key, 32);
    int packet_size = encrypt_packet(config.secret_key, connection_request_nonce, CLIENT_FLAG, (struct encrypted_packet *) con_req, 32);
    
    sendto(tunnel_socket, con_req_bytes, packet_size + 8, 0, (struct sockaddr *) &tunnel_addr, sizeof(tunnel_addr));

    printf("Connecting to tunnel at port %d...\n", config.tunnel_port);
    
    fcntl(tunnel_socket, F_SETFL, O_NONBLOCK);

    // Statistics
    uint64_t packets_count = 0;
    uint64_t packets_size = 0;

    // Main loop
    for (;;)
    {
        // Wait until a packet is available
        struct pollfd poll_fds[MAX_CONNECTIONS + 1];
        poll_fds[0].fd = tunnel_socket;
        poll_fds[0].events = POLLIN;
        for (int i = 1; i <= num_connections; i++)
        {
            poll_fds[i].fd = connections[i].socket;
            poll_fds[i].events = POLLIN;
        }
        poll(poll_fds, num_connections + 1, -1);

        // Receive a packet from the tunnel
        int data_len = recvfrom(tunnel_socket, packet.data, BUFFER_SIZE, 0, NULL, NULL);
        if (data_len == -1) {goto recv_from_minecraft;}

        // Decrypt the packet
        int packet_len = decrypt_packet(session_key, TUNNEL_FLAG, (struct encrypted_packet *) &packet, data_len);
        if (packet_len == -1) {
            printf("Forged packet\n");
            continue; // Forged packet, ignore it.
        }

        packets_count++;
        packets_size += packet_len;
        printf("Current Size: %8d  Avg: %8lu\n", packet_len, packets_size / packets_count);

        // Find the connection
        int connection_found = 0;
        int connection_index = -1;
        for (int i = 0; i < num_connections; i++)
        {
            if (connections[i].id == packet.connection_id)
            {
                connection_found = 1;
                connection_index = i;
                break;
            }
        }

        // If the connection was not found, create a new one
        if (!connection_found)
        {
            if (num_connections == MAX_CONNECTIONS)
            {
                // Try to find an inactive connection and replace it
                time_t current_time = time(NULL);
                for (int i = 0; i < num_connections; i++)
                {
                    if (current_time - connections[i].last_activity > MAX_CONNECTION_INACTIVITY)
                    {
                        close(connections[i].socket);
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

            struct connection new_connection;
            new_connection.id = packet.connection_id;
            new_connection.socket = socket(AF_INET, SOCK_DGRAM, 0);
            new_connection.addr.sin_family = AF_INET;
            new_connection.addr.sin_port = 0; // Bind to any available port
            new_connection.addr.sin_addr.s_addr = inet_addr("127.0.0.1");

            bind(new_connection.socket, (struct sockaddr *) &new_connection.addr, sizeof(new_connection.addr));
            fcntl(new_connection.socket, F_SETFL, O_NONBLOCK);

            connections[num_connections] = new_connection;
            num_connections++;

            printf("Created new connection with ID %d.\n", new_connection.id);
        }

        // Update the last activity time
        connections[connection_index].last_activity = time(NULL);

        // Send the packet to the Minecraft server, skipping the first 4 bytes
        sendto(connections[connection_index].socket, packet.data, packet_len - PACKET_HEADER_SIZE, 0, (struct sockaddr *) &minecraft_addr, sizeof(minecraft_addr));

        #ifdef TRACE
        printf("To minecraft server: message %d of len %d\n", recv_message_counter, buffer_len - 8);
        print_hex(buffer + 8, buffer_len - 8);
        #endif

        recv_from_minecraft:;

        // Receive packets from the Minecraft server
        for (int i = 0; i < num_connections; i++)
        {
            if (connections[i].socket == -1) continue;

            data_len = recvfrom(connections[i].socket, packet.data, BUFFER_SIZE, 0, NULL, NULL);
            if (data_len == -1) continue;

            packet.connection_id = connections[i].id;
            message_nonce_counter++;
            packet_len = encrypt_packet(session_key, message_nonce_counter, CLIENT_FLAG, (struct encrypted_packet *) &packet, data_len);
            sendto(tunnel_socket, &packet, packet_len, 0, (struct sockaddr *) &tunnel_addr, sizeof(tunnel_addr));

            packets_count++;
            packets_size++;
        }
    }
}
