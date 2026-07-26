# Custom VPN - SSH/SSL/SNI Tunnel

Android VPN application similar to HTTP Custom, supporting SSH Tunnel, SSL/TLS Tunnel, and custom SNI (Server Name Indication).

## Features

- **SSH Tunnel** - Direct SSH tunneling through SOCKS5 proxy
- **SSL/TLS Tunnel** - SSL/TLS encrypted tunneling with custom SNI
- **SSL/TLS + SSH** - Combined SSL/TLS front with SSH backend
- **Custom SNI** - Override SNI hostname for domain fronting
- **HTTP Payload** - Customizable HTTP headers for obfuscation
- **DNS over UDP** - DNS query forwarding through the tunnel
- **Connection Logs** - Real-time connection event logging
- **Config Management** - Save/load multiple server configurations
- **Dark Theme** - Modern Material Design dark interface

## Build

### GitHub Actions (Automatic)

Push to `main` or create a tag to trigger the build workflow:

```bash
git tag v1.0.0
git push origin v1.0.0
```

Download APK from the **Actions** tab → latest successful workflow → **Artifacts**.

### Local Build

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/vpn-http-custom-sni-ssl-tls.git
cd vpn-http-custom-sni-ssl-tls

# Build debug APK
./gradlew assembleDebug

# Build release APK (requires signing config)
./gradlew assembleRelease
```

APK output: `app/build/outputs/apk/debug/app-debug.apk`

## Connection Modes

| Mode | Description |
|------|-------------|
| SSH Tunnel | Direct SSH connection with SOCKS5 proxy |
| SSL/TLS + SSH | SSL/TLS encryption wrapping SSH tunnel |
| SSL/TLS + SNI | SSL/TLS with custom SNI for domain fronting |
| Direct SSH | Simple SSH tunnel without payload |

## Configuration

### Required Fields
- **Server Address** - IP or hostname of your server
- **Server Port** - SSL/TLS port (typically 443)
- **SSH Port** - SSH service port (typically 22)

### Optional Fields
- **SNI** - Custom Server Name Indication for SSL handshake
- **Payload** - Custom HTTP headers for SSH obfuscation
- **Username** - SSH authentication username
- **Password** - SSH authentication password

### Payload Format

Use placeholders in payload:
- `[crlf]` → Carriage return + line feed
- `[ua]` → User-Agent string
- `[random_key]` → Random 32-char string

Example:
```
GET / HTTP/1.1[crlf]
Host: sni.example.com[crlf]
Connection: Upgrade[crlf]
Upgrade: websocket; HTTP/1.1[crlf]
[crlf]
```

## Architecture

```
com.customvpn.app/
├── models/          # Data classes (VpnConfig, ConnectionState)
├── service/         # Android VPN Service
├── ssh/             # SSH tunnel implementation
├── ssl/             # SSL/TLS tunnel with SNI
├── ui/              # Activities, Adapters, UI
└── utils/           # Payload builder, Session manager
```

## Tech Stack

- Kotlin
- Android VpnService API
- Java NIO Sockets
- SSL/TLS (JSSE)
- Material Design Components
- Gradle Build System
- GitHub Actions CI/CD

## Requirements

- Android 7.0+ (API 24)
- VPN permission (granted at first connection)

## License

MIT License
