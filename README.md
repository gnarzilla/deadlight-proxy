# Deadlight Proxy
[Quick Start](#quick-start) · [Features](#features) · [API](#rest-api) · [Configuration](#configuration) · [Documentation](docs/) · [Architecture](#architecture) · [Roadmap](#roadmap) <br>

[![GitHub Release](https://img.shields.io/github/v/release/gnarzilla/deadlight-proxy)](https://github.com/gnarzilla/deadlight-proxy/releases/latest)
[![Docker Pulls](https://img.shields.io/docker/pulls/gnarzilla/proxy-deadlight)](https://hub.docker.com/r/gnarzilla/proxy-deadlight)
[![Docker Image Size](https://img.shields.io/docker/image-size/gnarzilla/proxy-deadlight/latest)](https://hub.docker.com/r/gnarzilla/proxy-deadlight)
[![GitHub License](https://img.shields.io/github/license/gnarzilla/deadlight-proxy)](LICENSE)


A lightweight, multi-protocol proxy server built for **real-world conditions**: intermittent connectivity, resource constraints, and hostile networks. Written in C with GLib, featuring automatic protocol detection, HTTP/S, SOCKS4/5, WebSocket, SMTP, IMAP/S, FTP, TLS interception, VPN gateway mode, REST API and embedded web UI.

**Multi-protocol in one binary** · **17.6 MB Docker image** · **Works on ARM64** · **REST API** · **Edge-native design**

<img src="src/assets/media/webui-4-25-26.gif" width="780" alt="UI with live connection table">

> **Security Notice:** This proxy can perform TLS interception.
> Only deploy on hardware you control. See [Security Considerations](#security-considerations).

<p align="center">
  <a href="https://ko-fi.com/s/bc2cb7c2ee" target="_blank">
    <img src="https://raw.githubusercontent.com/gnarzilla/blog.deadlight/main/src/assets/apple-touch-icon/App-Store-Logo-transp.png"
         width="88"
         alt="Download Deadlight Proxy">
  </a>
</p>

<h3 align="center">
  Android APK Available Now
</h3>

<details>
<summary>Android App</summary>

<div align="center">

<img src="https://raw.githubusercontent.com/gnarzilla/deadlight-proxy/main/src/assets/media/deadlight-app-start.jpg"
     width="260"
     alt="Deadlight Proxy startup screen">

<p><em>Startup screen</em></p>

<img src="https://raw.githubusercontent.com/gnarzilla/deadlight-proxy/main/src/assets/media/deadlight-app-running3.jpg"
     width="260"
     alt="Deadlight Proxy running">

<p><em>Live proxy monitoring</em></p>

<img src="https://raw.githubusercontent.com/gnarzilla/deadlight-proxy/main/src/assets/media/deadlight-app-shutdown.png"
     width="260"
     alt="Deadlight Proxy stopped">

<p><em>Shutdown state</em></p>

</div>

---

Samsung tablet with curl tests in Termux

<img src="src/assets/media/Screenshot_20260514_111354_Termux.jpg" width="520" alt="Android App on Tablet">

[Download](https://ko-fi.com/s/bc2cb7c2ee)

</details>


<details>
  <summary>Or Compile in Termux</summary>

```bash
proot-distro install debian
proot-distro login debian

git clone git@github.com/gnarzilla/deadlight-proxy.git
cd deadlight-proxy

make clean && make UI=1
```
<table>
  <tr>
    <td><img src="src/assets/media/Screenshot_20260503_201011_Termux.jpg" width="260"></td>
    <td><img src="src/assets/media/Screenshot_20260503_203338_Termux.jpg" width="260"></td>
    <td><img src="src/assets/media/Screenshot_20260503_211029_Termux.jpg" width="260"></td>
    <td><img src="src/assets/media/webui-mobile.jpg" width="260"</td>
  </tr>
</table>

</details>


## Quick Start

### Download Binary (Fastest)

Grab the latest release for your platform:

```bash
# Linux amd64
curl -LO https://github.com/gnarzilla/deadlight-proxy/releases/latest/download/deadlight-linux-amd64
chmod +x deadlight-linux-amd64
./deadlight-linux-amd64 -v

# Linux arm64 (Raspberry Pi, ARM servers)
curl -LO https://github.com/gnarzilla/deadlight-proxy/releases/latest/download/deadlight-linux-arm64
chmod +x deadlight-linux-arm64
./deadlight-linux-arm64 -v
```

Proxy runs on `:8080`, Web UI on `:8081`, API at `/api`.

### Docker

```bash
docker run -d \
  --name deadlight-proxy \
  -p 8080:8080 \
  -p 8081:8081 \
  gnarzilla/proxy-deadlight:latest

# Run with memory limits to prove efficiency
docker run -d --name deadlight-proxy \
  --memory="64m" --cpus="0.5" \
  -p 8080:8080 -p 8081:8081 \
  gnarzilla/proxy-deadlight:latest
```



<details>
<summary>Docker Compose</summary>

```yaml
version: '3.8'
services:
  proxy:
    image: gnarzilla/proxy-deadlight:latest
    ports:
      - "8080:8080"
      - "8081:8081"
    environment:
      - DEADLIGHT_AUTH_SECRET=your-secret-here
    volumes:
      - ./config:/etc/deadlight
      - ./federation:/var/lib/deadlight/federation
      - ./blog-cache:/var/lib/deadlight/blog
    restart: unless-stopped
```

</details>

**Platforms:** `linux/amd64`, `linux/arm64` (Raspberry Pi, ARM servers, Apple Silicon), `Android via Termux`

### Build from Source

<img src="src/assets/media/cli-boot-4-26-26.gif" width="780" alt="CLI boot">

<details>
<summary>Build instructions</summary>

**Requirements:** GLib 2.0+, OpenSSL 1.1+, GCC/Clang, json-glib-1.0
**Optional:** libmicrohttpd (for web UI)

```bash
# Install dependencies (Debian/Ubuntu)
sudo apt-get install build-essential pkg-config libglib2.0-dev \
  libssl-dev libjson-glib-dev libmicrohttpd-dev

# Build
git clone https://github.com/gnarzilla/deadlight-proxy.git
cd deadlight-proxy
make clean && make UI=1

# Run
./bin/deadlight -c deadlight-conf -v
```

</details>

### Verify It's Working

```bash
# HTTP proxy
curl -x http://localhost:8080 http://example.com

# Health check
curl http://localhost:8080/api/health

# Web UI
open http://localhost:8081
```

---

## Features

### Core Capabilities

| Feature | Description |
|---------|-------------|
| **Multi-Protocol** | HTTP/S, SOCKS4/5, WebSocket, SMTP, IMAP/S, FTP—auto-detected |
| **TLS Interception** | MITM HTTPS inspection with upstream cert mimicry |
| **Connection Pooling** | Reuses upstream connections with health checks |
| **VPN Gateway** | Kernel-integrated TUN device for Layer 3 routing |
| **REST API** | Email, federation, metrics, and management endpoints |
| **Blog Cache** | Read-through cache for blog.deadlight with offline fallback |
| **Plugins** | Ad blocking, rate limiting, custom filters |
| **Web UI** | SSE-powered real-time monitoring at `:8081` |
| **Resource-Efficient** | 17.6 MB Docker image, minimal RAM |

<img src="src/assets/media/webui-4-26-26.gif" width="780" alt="Web UI with connection table">

---

## REST API

### Quick Examples

```bash
# Health check
curl http://localhost:8080/api/health

# Send email
curl -X POST http://localhost:8080/api/email/send \
  -H "Content-Type: application/json" \
  -d '{"to":"user@example.com", "from":"user@deadlight.boo","subject":"Test","body":"Hello"}'

# View metrics
curl http://localhost:8080/api/metrics | jq

# Federation: Send post to another Deadlight instance
curl -X POST http://localhost:8080/api/federation/send \
  -H "Content-Type: application/json" \
  -d '{"target_domain":"other.deadlight.boo","content":"Hello!","author":"alice"}'
```

### Endpoints

| Category | Endpoint | Description |
|----------|----------|-------------|
| **System** | `GET /api/health` | Health check with version info |
| | `GET /api/system/ip` | External IP detection |
| | `GET /api/metrics` | Real-time connection/protocol/pool stats |
| | `GET /api/stream` | SSE real-time event stream |
| | `GET /api/dashboard` | Unified metrics + logs |
| | `GET /api/logs` | Log buffer |
| **Email** | `POST /api/email/send` | Send email (no auth) |
| | `POST /api/outbound/email` | Send email (HMAC auth required) |
| **Federation** | `POST /api/federation/send` | Send post to another instance |
| | `POST /api/federation/receive` | Receive federated posts |
| | `GET /api/federation/posts` | List stored posts |
| | `GET /api/federation/status` | Federation system status |
| | `GET /api/federation/test/{domain}` | Test domain connectivity |
| **Blog** | `GET /api/blog/posts` | List blog posts (cached) |
| | `GET /api/blog/status` | Blog system status |

**Full API documentation:** [docs/API.md](docs/API.md)

<details>
<summary>Federation Architecture</summary>

```
   Alice's Proxy                    Bob's Proxy
   (proxy.alice.deadlight)         (proxy.bob.deadlight)
         │                                │
         ├─ POST /api/federation/send     │
         │  {"target": "bob.deadlight"}   │
         │                                │
         └──> SMTP.                 ────┤
                                          │
                    ┌─────────────────────┘
                    │
                    ├─ POST /api/federation/receive
                    └─ Stores in /var/lib/deadlight/federation/
```

</details>

---

## Configuration

### Default Locations
- **Docker:** `/etc/deadlight/deadlight.conf` (auto-generated)
- **Native:** `/etc/deadlight/deadlight.conf`

### Key Sections

```ini
[core]
port = 8080
max_connections = 500
worker_threads = 4
auth_secret = <generate_with_openssl_rand>

[ssl]
enabled = true
ca_cert_file = /etc/deadlight/ca.crt
ca_key_file = /etc/deadlight/ca.key

[smtp]
mailchannels_api_key = <your_api_key>

[plugins]
enabled = true
autoload = adblocker,ratelimiter

[vpn]
enabled = false  # Requires root + --privileged
tun_device = tun0

[blog]
workers_url = https://deadlight.boo
cache_ttl = 300
enable_cache = true
cache_dir = /var/lib/deadlight/blog
```

**Hot-reload:** Config changes apply automatically (no restart needed).

**Generate auth secret:** `openssl rand -hex 32`

Example configs: [`deadlight.conf.example`](deadlight.conf.example), [`deadlight.conf.docker`](deadlight.conf.docker)

### Command-Line Options

```
-c, --config FILE   Config file (default: /etc/deadlight/deadlight.conf)
-p, --port PORT     Override listening port
-v, --verbose       Enable debug logging
-d, --daemon        Run as background daemon
-h, --help          Show usage
```

---

## Security Considerations

### TLS Interception

When enabled, the proxy terminates and re-encrypts TLS. This means:
- Plaintext is visible to the proxy process
- Plugins can inspect/modify decrypted traffic
- Credentials in requests are exposed to the proxy

**Recommendation:** Run on trusted hardware only.

<details>
<summary>Install CA Certificate</summary>

```bash
# Extract CA from Docker
docker run --rm gnarzilla/proxy-deadlight:latest cat /etc/deadlight/ca.crt > deadlight-ca.crt

# Debian/Ubuntu
sudo cp deadlight-ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates

# Fedora/RHEL
sudo cp deadlight-ca.crt /etc/pki/ca-trust/source/anchors/
sudo update-ca-trust

# macOS
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain deadlight-ca.crt

# Windows: Double-click → Install → Trusted Root Certification Authorities
# Firefox: about:preferences#privacy → Certificates → Authorities → Import
```

**Warning:** Only install on devices you control. Breaks certificate pinning on some sites.

</details>

<details>
<summary>Generate new CA Certificate</summary>
Generate CA certificate (for HTTPS interception):

Create the cert directory first, then generate a local CA:

```bash
mkdir -p ~/.deadlight

openssl genrsa -out ~/.deadlight/ca.key 4096
openssl req -new -x509 -days 3650 \
  -key ~/.deadlight/ca.key \
  -out ~/.deadlight/ca.crt \
  -subj "/CN=deadlight CA/O=deadlight/C=US"

chmod 600 ~/.deadlight/ca.key
chmod 644 ~/.deadlight/ca.crt
Install it system-wide so curl and other tools trust it:

sudo cp ~/.deadlight/ca.crt /usr/local/share/ca-certificates/deadlight.crt
sudo update-ca-certificates
```

</details>

### REST API Security

- API binds to `0.0.0.0` by default—restrict with `api_bind = 127.0.0.1`
- HMAC auth required for sensitive endpoints (`/api/outbound/*`)
- Federation endpoints accept unauthenticated POSTs (by design)

---

## Architecture

```
┌─────────────────┐
│  GSocketService │ ← Connection acceptance (port 8080)
└────────┬────────┘
         │
    ┌────▼─────┐
    │  Workers  │ ← Thread pool
    └────┬─────┘
         │
    ┌────▼──────────┐
    │  Detection     │ ← Protocol auto-detection
    └────┬──────────┘
         │
    ┌────▼─────────────────────────┐
    │  Protocol Handlers           │
    │  ├─ HTTP/HTTPS               │
    │  ├─ SOCKS4/5                 │
    │  ├─ API (REST endpoints)     │
    │  ├─ SMTP/IMAP                │
    │  ├─ WebSocket                │
    │  ├─ TLS Interception         │
    │  ├─ Connection Pool          │
    │  └─ Plugin Hooks             │
    └──────────────────────────────┘
```

**Design Philosophy:**
- **Stateless core** — no local DB/queues, federation uses filesystem
- **Edge-native** — optimized for intermittent connectivity
- **Plugin-extensible** — modify behavior without core changes
- **Performance-focused** — connection pooling, async I/O, worker threads
- **API-first** — RESTful interface for programmatic control

---

## Use Cases

| Scenario | How Deadlight Helps |
|----------|---------------------|
| **Home Gateway** | Secure all devices via VPN without exposing ports |
| **Development** | Inspect/modify API calls with TLS interception + plugins |
| **Email Bridge** | Send emails via REST API or tunnel legacy SMTP/IMAP |
| **Privacy Tool** | SOCKS proxy with built-in ad blocking |
| **Edge Networks** | Works on mesh/satellite/2G with intermittent connectivity |
| **Federation Node** | Inter-instance communication for distributed systems |
| **Monitoring Hub** | Real-time metrics via REST API for dashboards |

---

## Extending Deadlight

<details>
<summary>Add a Protocol Handler</summary>

1. Create `src/protocols/myprotocol.c`
2. Implement `detect`, `handle`, `cleanup` functions
3. Register in `src/core/protocols.c`
4. Rebuild: `make`

</details>

<details>
<summary>Add a Plugin</summary>

1. Create `src/plugins/myplugin.c`
2. Define hooks (`on_request_headers`, `on_response`, etc.)
3. Export with `G_MODULE_EXPORT`
4. Enable in config: `[plugins] autoload = myplugin`

</details>

See [docs/EXTENDING.md](docs/EXTENDING.md) for details.

---

## Roadmap

### Near-term (early 2026)
- [x] REST API with email sending
- [x] Federation system (experimental)
- [x] Connection pool metrics
- [x] Connection pool with TLS session reuse
- [x] Blog caching with offline fallback
- [x] Server-Sent Events for real-time dashboard
- [x] API rate limiting tested & vetted
- [x] Deeper TLS session management for pooled connections

### Medium-term (late 2026)
- [ ] Dynamic plugin loading (no rebuild required)
- [ ] Full IPv6 support
- [ ] Windows/macOS native builds
- [ ] Prometheus metrics export
- [ ] ActivityPub federation support

### Long-term
- [ ] HF radio transport layer for resilient, infrastructure-free networking

---

## Part of the Deadlight Ecosystem

- [blog.deadlight](https://github.com/gnarzilla/blog.deadlight) — Cloudflare Workers blog (<10 KB pages)
- [deadmesh](https://github.com/gnarzilla/deadmesh) — Internet-over-LoRa gateway
- [edge.deadlight](https://github.com/gnarzilla/edge.deadlight) — Unified edge platform

## Documentation

- **[API Reference](docs/API.md)** — Complete REST API documentation
- **[Quick Start Guide](docs/QUICK_START.md)** — Detailed setup instructions
- **[Architecture](docs/ARCHITECTURE.md)** — Technical deep dive
- **[Extending Deadlight](docs/EXTENDING.md)** — Plugin and protocol development
- **[Contributing](docs/CONTRIBUTING.md)** — How to contribute

## License

MIT License — see [LICENSE](LICENSE)

## Support

- **Issues:** [GitHub Issues](https://github.com/gnarzilla/deadlight-proxy/issues)
- **Donate:** [ko-fi.com/gnarzilla](https://ko-fi.com/gnarzilla)
- **Email:** gnarzilla@deadlight.boo

**Contributions welcome** — see [CONTRIBUTING.md](docs/CONTRIBUTING.md)
