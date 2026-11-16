# YADBP - Yet Another DPI Bypass Proxy

YADBP is an HTTP proxy that bypasses Deep Packet Inspection (DPI) by splitting the initial TLS ClientHello into small TCP writes. It does not terminate TLS, decrypt traffic, or modify the TLS record itself.

It was made for a niche DNS rotation setup for my use case. I use a private DNS server that is firewalled to a list of allowed IPs. Connecting to a VPN that changes my IP would break other DPI-bypass proxies that rely on DNS redirection unless I set DNS to a public resolver. This proxy fixes that:

- Normal lookups use the primary DNS server.
- If the primary fails and a fallback is configured, YADBP switches to the fallback and marks the primary as down.
- While a fallback is configured and the primary is down, a health check probes the primary periodically. Once it recovers, lookups switch back to the primary.

YADBP resolves destination hostnames itself. It is not a DNS server and does not intercept DNS queries made by the client.

## Features

- Breaks the initial TLS handshake into smaller pieces so DPI systems have a harder time identifying it.
- Optional domain blacklist: fragment the TLS ClientHello for selected hosts, or for every host when no blacklist is provided.
- Optional primary and fallback DNS servers with failover and recovery checks.

## Download

See [Releases](https://github.com/FuLygon/yadbp/releases).

## Usage

```text
yadbp [options]
```

By default, the YADBP HTTP proxy listens on `127.0.0.1:8888`.

### Options

| Option | Default | Description |
| --- | --- | --- |
| `-h` | `127.0.0.1` | Listening host. |
| `-p` | `8888` | Listening port. |
| `-blacklist` | none | Optional path to a blacklist file. |
| `-dns-primary` | none | Primary DNS server (`ip:port`). Omit to use the system resolver. |
| `-dns-fallback` | none | Optional fallback DNS server (`ip:port`). Requires `-dns-primary`. |
| `-dns-primary-timeout` | `2` | Seconds before a primary query times out and is marked down. |
| `-dns-primary-healthcheck` | `30` | Seconds between health checks while the primary is down. |
| `-log-level` | `silent` | `debug`, `info`, `warn`, `error`, `fatal`, or `silent`. |

The DNS options accept only literal IP addresses. A hostname such as `dns.example:53` is rejected; use an address such as `1.1.1.1:53`.

### Examples

```bash
# Local-only proxy on the default port
yadbp -h 127.0.0.1 -p 8888

# Use a primary DNS server with a public fallback
yadbp -h 127.0.0.1 -p 8888 -dns-primary 10.0.0.2:53 -dns-fallback 1.1.1.1:53

# Fragment only domains listed in blacklist.txt
yadbp -h 127.0.0.1 -p 8888 -blacklist blacklist.txt
```

## DNS behavior

- With both a primary and fallback, a primary timeout or non-`NXDOMAIN` lookup failure marks the primary down and sends lookups to the fallback.
- A name-not-found (`NXDOMAIN`) answer from the primary is treated as authoritative and does not trigger a fallback lookup (for compatibility with ad-blocking DNS).
- When a fallback is configured and the primary is down, it is probed every `-dns-primary-healthcheck` seconds by resolving `example.com`. A successful probe switches lookups back to the primary.

## Blacklist

The blacklist controls fragmentation only; it does not block or allow proxy access.

- If `-blacklist` is omitted, every TLS ClientHello is fragmented.
- If a blacklist is provided, only matching hosts are fragmented. Other hosts are still proxied, but their TLS records are forwarded unchanged.
- A listed domain also matches its subdomains. For example, `example.com` matches `a.example.com`.

The file format is one domain per line. Blank lines and lines beginning with `#` are ignored:

```text
# Domains that should be fragmented
example.com
example.org
example.net
```

## Build from source

### Requirements

- Go 1.27 or newer

### Build

```bash
git clone https://github.com/FuLygon/yadbp.git
cd yadbp
go build ./cmd/yadbp
```
