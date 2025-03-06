# ratnat

A program to expose UDP services running behind NAT to the internet via a secure tunnel. I created this so I could expose a Minecraft server when I couldn't port forward.

## Usage

Configuration is handle via a file. To generate a template, run:

```console
ratnat config-gen <path>
```

```console
ratnat client <config-file>
```

```console
ratnat server <config-file>
```

## Security

The client and tunnel are mutually authenticated using a shared secret key. All traffic across the tunnel is encypted with a session key using ChaCha20-Poly1305.