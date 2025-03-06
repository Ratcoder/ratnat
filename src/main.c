#include <string.h>
#include <sodium.h>
#include "config.h"


void print_usage(char *cmd);
int client(char*);
int server(char*);


int main(int argc, char *argv[])
{
    if (sodium_init() == -1) {
        printf("Failed to initialize libsodium\n");
        return 1;
    }

    if (argc != 3)
    {
        print_usage(argv[0]);
        return 1;
    }

    if (strncmp(argv[1], "client", sizeof("client")) == 0)
        return client(argv[2]);
    else if (strncmp(argv[1], "server", sizeof("server")) == 0)
        return server(argv[2]);
    else if (strncmp(argv[1], "config-gen", sizeof("config-gen")) == 0)
        return config_gen(argv[2]);
    else if (strncmp(argv[1], "help", sizeof("help")) == 0)
    {
        printf("Options:\n"); // TODO: Implement this
        return 0;
    }
    else
    {
        print_usage(argv[0]);
        return 1;
    }
}

void print_usage(char *cmd)
{
    printf("Usage:\n");
    printf("    %s client <config-file>\n", cmd);
    printf("    %s server <config-file>\n", cmd);
    printf("    %s config-gen <config-file>\n", cmd);
    printf("    %s help <config-file>\n", cmd);
}