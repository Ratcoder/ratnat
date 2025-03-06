#ifndef CONFIG_H
#define CONFIG_H


#include <stdint.h>


struct config
{
    uint8_t secret_key[32];
    uint16_t internal_port;
    uint16_t external_port;
    uint32_t tunnel_ip;
    uint16_t tunnel_port;
};


void read_config(char *filename, struct config *config);
int config_gen(char *path);


#endif