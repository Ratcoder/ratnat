# ratnat

A program to expose UDP services running behind NAT to the internet via a secure tunnel. I created this so I could expose a Minecraft server when I couldn't port forward.

## Usage

To start, generate a configuration file template:

```shell
ratnat config-gen <path>
```

```ini
# Generated key
secret-key=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
# The ip of the ratnat server
server-ip=
# The port used by the natnat tunnel
tunnel-port=
# The port of the internal service running behind NAT
internal-port=
# The port to expose the service on on the server
# Users can connect to tunnel-ip:external-port
external-port=
```

The completed configuration file needs to be copied to both the client (machine running behind the NAT) and the server (machine with the public IP).

```shell
ratnat client <config-file>
```

```shell
ratnat server <config-file>
```

## Security

The client and tunnel are mutually authenticated using a shared secret key. All traffic across the tunnel is encypted with a session key using ChaCha20-Poly1305.