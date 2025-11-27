# OpnWire

An application that automatically configures and maintains a Private Internet Access (PIA) WireGuard VPN connection through OPNsense firewall with dynamic port forwarding for qBittorrent. Includes a dockerfile to turn it into a container.

## Overview

This application automates the complete setup and maintenance of:
- WireGuard VPN connection to PIA servers that support port forwarding
- OPNsense WireGuard interface, gateway configuration and port forwarding
- Dynamic port forwarding from PIA
- Update qBittorrent when port number changes
- PIA port binding and keep-alive

I have a set of docker containers that go through a VLAN and this little application in a docker container can run along with these other applications and maintain the VPN connection, Gateway, Port forwarding for the VPN and OpnSense. 

## Prerequisites

- OPNsense firewall with:
  - Set up your VPN like this: https://docs.opnsense.org/manual/how-tos/wireguard-selective-routing.html
  - WireGuard plugin installed
  - WireGuard server instance named `PIA_WireGuard`
  - Gateway named `PIA_VPN_IP4`
  - Firewall alias named `PIAPortForward`, use this alias for the port on the Port Forward rule
- qBittorrent instance with Web UI enabled
- Private Internet Access (PIA) username and password
- Docker or compatible container runtime (I use podman)
- There's no option to allow self-signed certificates

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `PIA_USERNAME` | Yes | Your PIA account username |
| `PIA_PASSWORD` | Yes | Your PIA account password |
| `QBITTORRENT_URL` | Yes | qBittorrent Web UI URL (e.g., `http://qbittorrent:8080`) |
| `QBITTORRENT_USERNAME` | Yes | qBittorrent Web UI username |
| `QBITTORRENT_PASSWORD` | Yes | qBittorrent Web UI password |
| `OPNSENSE_URL` | Yes | OPNsense URL (e.g., `https://opnsense.local`) |
| `OPNSENSE_API_KEY` | Yes | OPNsense API key |
| `OPNSENSE_API_SECRET` | Yes | OPNsense API secret |

## Building the Docker Image

```bash
docker build -t opnwire-docker .
```

## Running the Container

```bash
docker run -d \
  --name opnwire \
  -e PIA_USERNAME=your_username \
  -e PIA_PASSWORD=your_password \
  -e QBITTORRENT_URL=http://qbittorrent:8080 \
  -e QBITTORRENT_USERNAME=admin \
  -e QBITTORRENT_PASSWORD=adminpass \
  -e OPNSENSE_URL=https://opnsense.local \
  -e OPNSENSE_API_KEY=your_key \
  -e OPNSENSE_API_SECRET=your_secret \
  -v $(pwd)/data:/App/data \
  localhost/opnwire:latest
```

## License

This project is provided as-is for personal use.