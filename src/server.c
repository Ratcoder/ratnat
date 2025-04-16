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
#include <errno.h>


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
    struct generic_packet packet;
    struct service_packet *service_packet = (struct service_packet *) &packet;

    // State for tunnel connection
    int is_authenticated = 0;
    uint8_t auth_challenge[64];
    uint64_t message_nonce_counter = 4;
    uint8_t session_key[32];

    printf("Tunnel listening on port %d for service on port %d\n", config.tunnel_port, config.external_port);

    for (;;)
    {
        // Wait until a packet is available
        struct pollfd poll_fds[2];
        poll_fds[0].fd = tunnel_socket;
        poll_fds[0].events = POLLIN;
        poll_fds[1].fd = minecraft_socket;
        poll_fds[1].events = POLLIN;
        poll(poll_fds, 2, -1);

        // Receive a packet from the tunnel client
        struct sockaddr_in recv_addr;
        socklen_t recv_addr_len = sizeof(recv_addr);
        int data_len = recvfrom(tunnel_socket, &packet, BUFFER_SIZE, 0, (struct sockaddr *) &recv_addr, &recv_addr_len);
        if (data_len == -1) {
            goto recv_from_minecraft;
        }

        // Handle connection requests
        if (packet.type == MSG_CONNECTION_REQUEST)
        {
            // Decrypt the packet
            int packet_len = decrypt_packet(&packet, data_len, CLIENT_FLAG, config.secret_key);
            if (packet_len == -1) {
                printf("Rejected connection request\n");
                continue; // Forgery detected, ignore the packet
            }
            if (packet_len != sizeof(struct connection_request_packet)) continue;

            printf("Client connected\n");
            tunnel_addr = recv_addr;
            is_authenticated = 1;
            struct connection_request_packet *con_req = (struct connection_request_packet *) &packet;
            memcpy(session_key, con_req->session_key, 32);

            uint64_t connection_accepted = MSG_CONNECTION_ACCEPTED;
            sendto(tunnel_socket, &connection_accepted, sizeof(connection_accepted), 0, (struct sockaddr *) &tunnel_addr, address_len);
            continue;
        }

        if (!is_authenticated) continue;

        // Decrypt the packet
        int packet_len = decrypt_packet(&packet, data_len, CLIENT_FLAG, session_key);
        if (packet_len == -1) {
            printf("Decryption failed\n");
            continue; // Forgery detected, ignore the packet
        }
        // Reject all packets not from the tunnel client
        if (recv_addr.sin_addr.s_addr != tunnel_addr.sin_addr.s_addr || recv_addr.sin_port != tunnel_addr.sin_port)
        {
            printf("Received packet from unknown source.\n");
            continue;
        }

        // Handle service packets
        if (packet.type != MSG_SERVICE || packet_len < SERVICE_PACKET_HEADER_SIZE)
        {
            printf("Invalid packet type\n");
            continue;
        }
        data_len = packet_len - SERVICE_PACKET_HEADER_SIZE;

        // Find the connection
        for (int i = 0; i < num_connections; i++)
        {
            if (connections[i].id == service_packet->connection_id)
            {
                #ifdef TRACE
                printf("To minecraft client: message %d of len %d\n", recv_message_counter, buffer_len - 8);
                print_hex(buffer + 8, buffer_len - 8);
                #endif
                
                // Forward the packet to the minecraft client
                sendto(minecraft_socket, service_packet->data, data_len, 0, (struct sockaddr *) &connections[i].addr, sizeof(connections[i].addr));
                break;
            }
        }

        recv_from_minecraft:;

        // Receive packets from the minecraft clients
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        data_len = recvfrom(minecraft_socket, service_packet->data, BUFFER_SIZE, 0, (struct sockaddr *) &client_addr, &client_addr_len);
        if (data_len == -1) {
            continue;
        }

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

            connection_index = num_connections;
            connections[connection_index].id = connection_id_counter++;
            connections[connection_index].addr = client_addr;
            num_connections++;
            printf("Created new connection with ID %d\n", connections[connection_index].id);
        }

        // Update the last activity time
        connections[connection_index].last_activity = time(NULL);
        service_packet->type = MSG_SERVICE;
        service_packet->connection_id = connections[connection_index].id;

        // Encrypt the packet
        message_nonce_counter++;
        packet_len = data_len + SERVICE_PACKET_HEADER_SIZE;
        packet_len = encrypt_packet((struct generic_packet *) service_packet, packet_len, TUNNEL_FLAG, session_key, message_nonce_counter);
        sendto(tunnel_socket, service_packet, packet_len, 0, (struct sockaddr *) &tunnel_addr, sizeof(tunnel_addr));
    }
}