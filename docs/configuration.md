# ProxiFyre configuration reference

ProxiFyre reads `app-config.json` from the directory containing the resolved `ProxiFyre.exe`. The GUI is the recommended editor: it validates the complete model, preserves unknown JSON properties, writes atomically, and keeps the previous file as `app-config.json.bak`.

Configuration changes do not alter a running service. Use **Apply & Restart** in the GUI, or restart `ProxiFyreService` after editing the file manually.

## Optional unelevated console mode

The normal GUI and Windows service workflows remain elevated. A portable manager can instead start the engine in an explicitly limited, interactive console mode:

```console
ProxiFyre.exe --allow-not-admin
```

`--allow-not-admin` is an exact, case-sensitive opt-in and is accepted only for a normal interactive run. It cannot be combined with Topshelf's `install`, `uninstall`, `start`, or `stop` lifecycle commands or its `command` service-control verb, and it has no effect on service execution. Windows Packet Filter must already be installed and accessible; if the engine cannot open the driver, startup fails instead of silently running without redirection. The engine writes a prominent warning to the console and log whenever the limited mode is active.

Process ownership lookup is best effort for a standard user. ProxiFyre can route applications it resolves normally, but Windows may deny access to protected, elevated, system, or other-user processes. Traffic with an unresolved owner remains direct, including when the configuration contains the `"appNames": [""]` catch-all. This fail-direct behavior prevents an unresolved privileged process from being mistaken for an ordinary catch-all match, but it also means the mode is **not** a strict current-user isolation or leak-prevention boundary. Use the elevated service when complete machine-wide attribution and enforcement are required.

## Complete example

```json
{
  "logLevel": "Info",
  "bypassLan": true,
  "proxies": [
    {
      "appNames": ["chrome", "firefox"],
      "socks5ProxyEndpoint": "proxy.example.com:1080",
      "username": "example-user",
      "password": "example-password",
      "socks5Transport": "TCP",
      "supportedProtocols": ["TCP", "UDP"],
      "supportedAddressFamilies": ["IPv4", "IPv6"]
    },
    {
      "appNames": [""],
      "socks5ProxyEndpoint": "tls-proxy.example.com:443",
      "socks5Transport": "TLS",
      "tlsServerName": "tls-proxy.example.com",
      "tlsPinnedSha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "tlsAllowInvalidCertificate": false,
      "supportedProtocols": ["TCP"],
      "supportedAddressFamilies": ["IPv4"]
    }
  ],
  "excludes": [
    "vpn-client.exe",
    "C:\\Program Files\\Local App\\NotProxied.exe"
  ]
}
```

## Top-level properties

| Property | Description |
| --- | --- |
| `logLevel` | `Error`, `Warning`, `Info`, `Debug`, or `All`. Missing or unsupported values fall back to `Info`. |
| `bypassLan` | When `true`, supported local IPv4 ranges remain direct. Default: `false`. |
| `proxies` | One or more ordered routing rules. The first matching rule wins. |
| `excludes` | Process names or paths that always bypass proxy routing. |

## Routing rule properties

| Property | Description |
| --- | --- |
| `appNames` | Application names or paths matched by this rule. An explicit empty string is the catch-all. |
| `socks5ProxyEndpoint` | SOCKS5 hostname or IPv4 address plus port, for example `proxy.example.com:1080`. |
| `username`, `password` | Optional SOCKS5 authentication. Configure both or neither. |
| `socks5Transport` | `TCP` for normal SOCKS5 or `TLS` for SOCKS5-over-TLS. Default: `TCP`. |
| `tlsServerName` | TLS SNI and certificate-validation name. Defaults to the endpoint hostname. |
| `tlsPinnedSha256` | Optional SHA-256 fingerprint of the expected leaf certificate. |
| `tlsAllowInvalidCertificate` | Disables normal certificate validation. Default: `false`; avoid this without a pin. |
| `supportedProtocols` | `TCP`, `UDP`, or both. Omitted means both. |
| `supportedAddressFamilies` | `IPv4`, `IPv6`, or both. Omitted means both. |

## Application matching and rule order

Routing rules are evaluated from top to bottom. The first matching rule wins.

- A value containing neither `/` nor `\` matches the whole executable name, case-insensitively. `firefox` and `firefox.exe` match `firefox.exe`; `firefox` does not match `NewFirefox.exe`.
- A value containing `/` or `\` is matched as a substring of the process's full path. This is useful for applications installed beneath a variable package directory.
- An explicit empty string (`""`) matches every application not already matched or excluded. Put this catch-all rule last because it shadows every later rule.
- Null and whitespace-only entries are ignored; spaces are not a catch-all.

The validator warns about duplicate, overlapping, or shadowed matches without changing rule order.

At least one proxy rule is required. A rule with no meaningful `appNames` entry is retained for compatibility but never matches a process, and validation reports a warning.

## Exclusions

Exclusions take priority over all routing rules, including the catch-all. They deliberately use permissive substring matching: a name is compared with the process filename and a path-form entry with the full path. For example, `chrome` also excludes `chrome_proxy.exe`.

When ProxiFyre is used alongside another VPN or tunnel, exclude that product's carrier process if necessary. Otherwise a catch-all rule can capture the outer tunnel traffic and make the proxy connection recursively depend on itself.

## Protocols and address families

`supportedProtocols` accepts `TCP`, `UDP`, or both. Omission means both for backward compatibility. An explicit empty list also retains the legacy both-protocol behavior, but the GUI requires newly edited rules to select at least one protocol.

`supportedAddressFamilies` accepts `IPv4`, `IPv6`, or both. Omission means both; an explicit empty list or an unknown value is invalid.

If a matched rule does not support the destination address family, ProxiFyre blocks that traffic instead of allowing it to pass directly or sending it to an incompatible SOCKS path. Selecting only `IPv4`, for example, prevents an IPv6 leak while allowing applications such as browsers to fall back to IPv4.

IPv6 destination routing also requires:

- working IPv6 connectivity on the client, because ProxiFyre redirects packets the application emits rather than creating IPv6 reachability;
- a SOCKS5 server that accepts IPv6 target addresses (`ATYP=4`); and
- an upstream proxy reachable through IPv4. The endpoint itself must be an IPv4 literal or a hostname with an A record; IPv6-literal and AAAA-only upstreams are not supported.

Fragmented IPv6 datagrams are passed through directly to avoid rewriting an incomplete packet. Applications that emit oversized fragmented UDP datagrams can therefore bypass the proxy; TCP and path-MTU-aware UDP such as normal QUIC traffic are unaffected.

## LAN bypass

Set `bypassLan` to `true` to keep these local IPv4 destinations direct while matched internet traffic uses the proxy:

- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`
- `169.254.0.0/16` (link-local/APIPA)
- `224.0.0.0/4` (multicast)

Changing this setting requires a service restart.

## Authentication

Omit `username` and `password` when the SOCKS5 server does not require authentication. When authentication is enabled, both properties are required and each value must encode to no more than 255 bytes for the native SOCKS5 protocol.

Credentials remain plaintext in `app-config.json` because the service must read them. The GUI masks passwords and redacts configured or detected secret forms from diagnostics and recent-log summaries.

## SOCKS5 over TLS

Set `socks5Transport` to `"TLS"` for a TLS-protected SOCKS5 connection. This protects TCP `CONNECT` traffic and the UDP `ASSOCIATE` control channel; SOCKS5 UDP relay datagrams do not travel inside that TLS stream.

For a publicly trusted certificate, normally set only `tlsServerName` or allow it to default to the endpoint hostname. Normal Windows certificate-chain and hostname validation remains active.

For a self-signed laboratory endpoint, prefer `tlsPinnedSha256`. The pin is the expected leaf certificate's 32-byte SHA-256 fingerprint written as 64 hexadecimal characters; whitespace, colons, and hyphens are ignored during normalization. Pinning authenticates that exact certificate without requiring a public chain.

`tlsAllowInvalidCertificate: true` disables normal certificate validation and produces a prominent warning. With no pin, it disables upstream identity verification completely. The native transport currently negotiates TLS 1.2.

[Alighieri](https://github.com/wiresock/alighieri) provides a compatible SOCKS5-over-TLS listener.

## Logging

| Level | Intended use |
| --- | --- |
| `Error` | Failures only. |
| `Warning` | Failures and potentially unsafe or degraded conditions. |
| `Info` | Service lifecycle and configuration summaries. |
| `Debug` | Adds per-connection routing, proxy negotiation, and relay details. |
| `All` | Maximum native and managed detail. |

Engine logs are written beneath the `logs` directory beside `ProxiFyre.exe`. Changing `logLevel` requires a service restart. The Logs-tab **View filter** is display-only: it filters lines already written and does not change engine verbosity or require a restart.

For log following, rotation, file access, and troubleshooting, see [gui.md](gui.md#logs-and-notification-area).
