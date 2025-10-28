# Xray VPN Server Installation Guide

This guide helps you install and configure Xray VPN server on Ubuntu/Debian.

## Prerequisites

- Ubuntu 18.04+ or Debian 10+
- Root access or sudo privileges
- Open ports: 443 (or your configured port)

## Quick Installation

1. Update system and install curl:
```bash
apt update && apt upgrade -y
apt install curl -y
```

2. Download and run installation script:
```bash
curl -O https://raw.githubusercontent.com/ecspecial/xray_vpn/main/xray_install.sh
chmod +x xray_install.sh
./xray_install.sh
```

## Command Reference

### User Management

#### Main User Setup
```bash
mainuser
```
- Creates primary user account
- Generates VLESS configuration
- Shows connection details and QR code

#### Add New User
```bash
newuser
```
- Adds additional user account
- Generates unique UUID
- Shows new user connection details

#### Remove User
```bash
rmuser
```
- Lists existing users
- Select user to remove by number
- Confirms removal

### Configuration

#### Generate Share Link
```bash
sharelink
```
- Generates shareable VLESS link
- Shows QR code for easy import
- Lists all user share links

#### Change SNI (Server Name Indication)
```bash
changesni
```
- Updates SNI settings
- Helps bypass restrictions
- Restarts service automatically



## Post-Installation

- Configuration file location: `/usr/local/etc/xray/config.json`

## Verification

1. Check if service is running:
```bash
systemctl status xray
```

2. Verify listening ports:
```bash
netstat -tulpn | grep xray
```

## Troubleshooting

1. If service fails to start:
```bash
journalctl -u xray -f
```

2. Check configuration:
```bash
xray test -config /usr/local/etc/xray/config.json
```

## Uninstallation

To remove Xray:
```bash
systemctl stop xray
rm -rf /usr/local/etc/xray
rm /etc/systemd/system/xray.service
systemctl daemon-reload
```
