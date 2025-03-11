#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sodium.h>
#include <string.h>
#include "config.h"

// Reads `srclen` bytes from a hex string `src` and stores it as `srclen` / 2 bytes in `dest`.
static int read_hex(char *dest, const char *src, int srclen)
{
    if (srclen % 2 != 0) return -1;

    #define value(a) \
        ( a >= '0' && a <= '9' ? a - '0' \
        : a >= 'a' && a <= 'z' ? a - 'a' + 10 \
        : a >= 'A' && a <= 'Z' ? a - 'A' + 10 \
        : -1)

    for (int i = 0; i < srclen / 2; i++)
    {
        char high = value(src[i * 2]);
        char low = value(src[i * 2 + 1]);
        if (low == -1 || high == -1) return -1;
        dest[i] = high * 16 + low;
    }

    return srclen / 2;
}

static int write_hex(char *dest, const char *src, int srclen)
{
    for (int i = 0; i < srclen; i++)
    {
        int low = ((unsigned char*) src)[i] & 0b00001111;
        int high = ((unsigned char*) src)[i] >> 4;
        dest[i * 2] = high >= 10 ? 'a' + high - 10 : '0' + high;
        dest[i * 2 + 1] = low >= 10 ? 'a' + low - 10 : '0' + low;
    }
    dest[srclen * 2] = 0; // Null terminate
    return srclen * 2;
}

void read_config(char *filename, struct config *config)
{
    int fd = open(filename, O_RDONLY);
    if (fd == -1)
    {
        fprintf(stderr, "Error reading config file: IO error.\n");
        exit(1);
    }

    struct stat filestats;
    if (fstat(fd, &filestats) == -1)
    {
        fprintf(stderr, "Error reading config file: IO error.\n");
        exit(1);
    }

    int buffer_length = filestats.st_size;
    char *buffer = malloc(buffer_length);
    int buffer_offset = 0;
    int bytes_read;
    if (buffer == NULL)
    {
        fprintf(stderr, "Error reading config file: Malloc.\n");
        exit(1);
    }

    while ((bytes_read = read(fd, buffer + buffer_offset, buffer_length - buffer_offset)) > 0)
    {
        buffer_offset += bytes_read;
    }

    if (bytes_read == -1)
    {
        fprintf(stderr, "Error reading config file: IO error.\n");
        exit(1);
    }

    if (close(fd) == -1)
    {
        fprintf(stderr, "Error reading config file: IO error.\n");
        exit(1);
    }

    // Parse file
    int variable = -1; // The current variable being parsed, -1 means no variable
    char *variables[] = {
        "secret-key",
        "internal-port",
        "external-port",
        "tunnel-port",
        "server-ip"
    };
    const int nbr_of_vars = sizeof(variables) / sizeof(char*);
    int is_var_defined[nbr_of_vars];
    memset(is_var_defined, 0, sizeof(is_var_defined) / sizeof(int));

    for(int right_pointer, left_pointer = 0; right_pointer < buffer_length; right_pointer++)
    {
        if (buffer[right_pointer] == '=')
        {
            int found_var = 0;
            for (int i = 0; i < nbr_of_vars; i++)
            {
                if (strncmp(variables[i], buffer + left_pointer, right_pointer - left_pointer) == 0)
                {
                    variable = i;
                    left_pointer = right_pointer + 1;
                    found_var = 1;
                    break;
                }
            }
            if (!found_var)
            {
                fprintf(stderr, "Error reading config file: unknown variable: ");
                write(STDERR_FILENO, buffer + left_pointer, right_pointer - left_pointer);
                fprintf(stderr, "\n");
                exit(1);
            }
        }
        else if (buffer[right_pointer] == '\n' || buffer[right_pointer] == '\r')
        {
            int value_length = right_pointer - left_pointer;
            char port[6]; // Maximum port 65535 is 5 bytes plus null
            char ip[16]; // Longest ip is 15 bytes (xxx.xxx.xxx.xxx) plus null
            switch (variable)
            {
            case 0: // secret-key
                if (value_length != 32 * 2)
                {
                    fprintf(stderr, "Error reading config file: s1ecret-key must be 32 bytes in hexidecimal.\n");
                    exit(1);
                }
                if (read_hex(config->secret_key, buffer + left_pointer, 64) == -1)
                {
                    fprintf(stderr, "Error reading config file: secret-key must be 32 bytes in hexidecimal.\n");
                    exit(1);
                }
                break;
            case 1: // internal-port
                memset(port, 0, 6);
                memcpy(port, buffer + left_pointer, value_length < 6 ? value_length : 6);
                config->internal_port = atoi(port);
                if (config->internal_port < 1024 || config->internal_port > 65535)
                {
                    fprintf(stderr, "Error reading config file: port must be between 1024-65535.\n");
                    exit(1);
                }
                break;
            case 2: // external-port
                memset(port, 0, 6);
                memcpy(port, buffer + left_pointer, value_length < 6 ? value_length : 6);
                config->external_port = atoi(port);
                if (config->external_port < 1024 || config->external_port > 65535)
                {
                    fprintf(stderr, "Error reading config file: port must be between 1024-65535.\n");
                    exit(1);
                }
                break;
            case 3: // tunnel-port
                memset(port, 0, 6);
                memcpy(port, buffer + left_pointer, value_length < 6 ? value_length : 6);
                config->tunnel_port = atoi(port);
                if (config->internal_port < 1024 || config->internal_port > 65535)
                {
                    fprintf(stderr, "Error reading config file: port must be between 1024-65535.\n");
                    exit(1);
                }
                break;
            case 4: // server-ip
                memset(port, 0, 6);
                memcpy(ip, buffer + left_pointer, value_length < 16 ? value_length : 16);
                config->tunnel_ip = inet_addr(ip);
                if (config->tunnel_ip == -1)
                {
                    fprintf(stderr, "Error reading config file: Invalid server-ip.\n");
                    exit(1);
                }
                break;
            }
            left_pointer = right_pointer + 1;

            if (variable >= 0 && variable < nbr_of_vars)
            {
                is_var_defined[variable] = 1;
                variable = -1;
            }
        }
        else if (buffer[right_pointer] == '#')
        {
            while (buffer[right_pointer] != '\n' && buffer[right_pointer] != '\r' && right_pointer < buffer_length)
            {
                right_pointer++;
            }
            left_pointer = right_pointer + 1;
        }
    }

    free(buffer);

    for (int i = 0; i < nbr_of_vars; i++)
    {
        if (!is_var_defined[i])
        {
            fprintf(stderr, "Error reading config file: %s not defined.\n", variables[i]);
            exit(1);
        }
    }

    close(fd);
}

int config_gen(char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd == -1)
    {
        fprintf(stderr, "Error creating file at %s.\n", path);
        return 1;
    }

    uint8_t key_bytes[32];
    char key_string[65];
    randombytes_buf(key_bytes, 32);
    write_hex(key_string, key_bytes, 32);

    dprintf(fd, "# Generated key\n");
    dprintf(fd, "secret-key=%s\n", key_string);
    dprintf(fd, "# The ip of the ratnat server\n");
    dprintf(fd, "server-ip=\n");
    dprintf(fd, "# The port used by the ratnat tunnel\n");
    dprintf(fd, "tunnel-port=\n");
    dprintf(fd, "# The port of the internal service running behind NAT\n");
    dprintf(fd, "internal-port=\n");
    dprintf(fd, "# The port to expose the service on\n");
    dprintf(fd, "# Users can connect to server-ip:external-port\n");
    dprintf(fd, "external-port=\n");
    
    close(fd);
    return 0;
}
