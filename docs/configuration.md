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
      "id": "office",
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
  ],
  "dns": {
    "mode": "Proxy",
    "proxyId": "office",
    "serverOverride": "1.1.1.1"
  }
}
```

## Top-level properties

| Property | Description |
| --- | --- |
| `logLevel` | `Error`, `Warning`, `Info`, `Debug`, or `All`. Missing or unsupported values fall back to `Info`. |
| `bypassLan` | When `true`, supported local IPv4 ranges remain direct. Default: `false`. |
| `proxies` | One or more ordered routing rules. The first matching rule wins. |
| `excludes` | Process names or paths that always bypass proxy routing. |
| `dns` | Optional global DNS routing. Omitted means `Direct`. See [DNS routing](#dns-routing). |

## Routing rule properties

| Property | Description |
| --- | --- |
| `id` | Optional stable identifier used to reference this rule's proxy, for example from `dns.proxyId`. 1–64 letters, digits, `-`, `_`, or `.`; unique, case-insensitive. Unlike the rule position it survives reordering. An empty or whitespace id means no id. An invalid or duplicate id is an error only when `dns.proxyId` in `Proxy` mode refers to it; otherwise it is reported as a warning, has no effect, and is removed when the configuration is saved (the first rule with a duplicated id keeps it). |
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

Fragmented IPv6 datagrams are passed through directly to avoid rewriting an incomplete packet. Applications that emit oversized fragmented UDP datagrams can therefore bypass the proxy; TCP and path-MTU-aware UDP such as normal QUIC traffic are unaffected. There are two exceptions, both for first fragments, which are the only fragments that carry ports: a first fragment addressed to port 53 is dropped in DNS `Proxy` mode (see [Proxy mode](#proxy-mode)), and a first fragment sent by one of ProxiFyre's local proxy listeners is dropped in every mode (see [Local listener replies and TCP close handling](#local-listener-replies-and-tcp-close-handling)).

## LAN bypass

Set `bypassLan` to `true` to keep these local IPv4 destinations direct while matched internet traffic uses the proxy:

- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`
- `169.254.0.0/16` (link-local/APIPA)
- `224.0.0.0/4` (multicast)

Changing this setting requires a service restart.

In DNS `Proxy` mode, DNS takes precedence over LAN bypass: a query addressed to a LAN resolver such as `192.168.1.1:53` is still sent through the DNS proxy, while all other LAN traffic stays direct. See [DNS routing](#dns-routing).

## Local listener replies and TCP close handling

ProxiFyre redirects a matched connection to a local listener and translates the listener's replies back before the application sees them. Two rules apply to every proxied connection, not only to DNS:

- **A reply that cannot be translated back is dropped.** A reply from a local listener is addressed to the original server only because redirection swapped the addresses, so it must never reach the network. It is dropped when its TCP connection or UDP endpoint is no longer tracked, when it is the first fragment of a fragmented reply, or when its SOCKS5 relay header is malformed or of the other address family. Earlier releases passed such packets toward the original server. The first such drop after the service starts is logged once as a warning, and a count is logged at `Info` level at most every five seconds while drops continue. Later fragments of a fragmented reply carry no ports, cannot be attributed to a listener, and are still passed.
- **A TCP connection is tracked through its whole close.** The FIN/ACK exchange is translated in both directions instead of reaching the real server. A reset (RST) ends the connection immediately; segments the local proxy had already sent when the reset arrived are dropped without the warning and are counted at `Debug` level only.

A proxied TCP connection that stays idle for more than 5 minutes loses its redirect entry; see [Limitations](#limitations).

## DNS routing

The optional `dns` object controls conventional DNS: UDP and TCP traffic to destination port 53, for IPv4 and IPv6. It is a global policy that applies to every process, independently of `appNames` rules and `excludes`. Windows normally resolves names in the DNS Client service (`Dnscache`, hosted by `svchost.exe`) rather than in the requesting application, so a per-application DNS rule could not be attributed reliably; ProxiFyre therefore does not try to.

| Property | Description |
| --- | --- |
| `mode` | `Direct` (default when `dns` or `mode` is omitted) or `Proxy`, case-insensitive. |
| `proxyId` | Required in `Proxy` mode: the `id` of the proxy rule whose SOCKS5 proxy carries DNS. That rule must support both `TCP` and `UDP` (omitting `supportedProtocols` means both). |
| `serverOverride` | Optional, `Proxy` mode only: an IPv4 or IPv6 literal with an optional port that the SOCKS5 proxy queries instead of the server Windows addressed, for example `1.1.1.1`, `1.1.1.1:53`, `2606:4700:4700::1111`, or `[2606:4700:4700::1111]:53`. Host names are rejected so the override never needs DNS itself. |

Configurations written before DNS routing existed load and save unchanged. The exceptions are configurations that already contained a rule property named `id` or a top-level property named `dns`. Earlier releases preserved and ignored both; they are now interpreted:

- A rule `id` that is invalid or duplicated, including one that is not a string, is only a warning unless DNS `Proxy` mode refers to it, so such a configuration still starts; the GUI removes it on the next save. An empty `id` means no id.
- A `dns` value must be an object (or `null`, which means `Direct`), and its `mode`, `proxyId`, and `serverOverride` must not be objects or arrays. Anything else, such as `"dns": "8.8.8.8"`, is a configuration error that names the property, and the service does not start until it is removed or replaced with a DNS policy object.

### Direct mode

UDP and TCP DNS to port 53 bypass every SOCKS5 proxy for both address families, whatever process sends it. This is the behavior of configurations without a `dns` section.

> **Behavior change on upgrade:** earlier releases bypassed only UDP port 53. TCP port 53 was routed like any other TCP traffic of the owning process, so a catch-all or application rule could send it through a proxy. In `Direct` mode, which also applies to existing configurations without a `dns` section, TCP/53 is now always direct as well, so DNS uses one consistent path whether or not an answer was truncated. Rules that previously carried TCP port 53 through a proxy no longer do so; use `Proxy` mode to route DNS through a proxy.

### Proxy mode

All captured UDP and TCP DNS is sent through the selected proxy. Queries from the Windows DNS Client service and from applications with their own resolvers are treated the same.

- **UDP** goes through one SOCKS5 control connection and one `UDP ASSOCIATE` per address family, shared by every query (see [Shared UDP association](#shared-udp-association)).
- **TCP** goes through a SOCKS5 `CONNECT` per connection, the same path as application TCP traffic.

ProxiFyre never falls back to sending DNS directly. The DNS policy itself drops a query when:

- the selected proxy could not be created at startup, or the configuration is rejected by the engine;
- the proxy does not accept the destination's address family (for example IPv6 DNS with an IPv4-only rule);
- a `serverOverride` is configured and the query is addressed to a server of the other address family (an IPv4 override blocks queries to IPv6 servers and vice versa);
- the packet cannot be redirected, such as a TCP connection to port 53 that was opened before ProxiFyre started, or a datagram too large to carry the SOCKS5 UDP header;
- a UDP datagram is too short to carry a DNS header (12 bytes): the shared association tells answers apart by DNS message ID, so it cannot be relayed;
- the datagram is fragmented. Only the first fragment carries the UDP or TCP header, so only a first fragment (IPv4 or IPv6) addressed to port 53 can be recognized as DNS; it is dropped, which also prevents the datagram from being reassembled at the server. Later fragments carry no ports, cannot be classified, and are passed unchanged, so other fragmented traffic is not affected. In `Direct` mode fragmented DNS is passed like any other DNS; or
- it is addressed to a configured SOCKS5 server and its sending process cannot be determined (see [Recursion and ProxiFyre's own traffic](#recursion-and-proxifyres-own-traffic)).

For these drops the engine logs one warning per cause, address family, and transport, followed by a count of dropped packets at most every five seconds.

A query can also fail after it has been redirected to the DNS proxy's local listener: the SOCKS5 connection, authentication, TLS handshake, or `UDP ASSOCIATE` fails, or the proxy disconnects. The query is then not sent directly either. For TCP these failures are reported by the local proxy server in the same way as for application traffic; for UDP, see [Shared UDP association](#shared-udp-association).

Whether name resolution still succeeds after a drop depends on Windows: it retries, and may try its other configured DNS servers, but ProxiFyre does not control that.

Windows retries a failed query and, for UDP answers marked truncated, retries over TCP; both go through the same proxy. ProxiFyre does not inspect payloads to decide what is DNS: only destination port 53 is classified.

If the selected proxy cannot be created when the service starts (for example its host name does not resolve or its listeners cannot be opened), the service still starts but **all DNS is blocked until the service is restarted** after the cause is fixed. The engine log says so explicitly. An unknown `mode` value stops the service from starting instead of being treated as `Direct`.

The selection is made by `proxyId`, never by position, so reordering rules does not change the DNS proxy. If the referenced rule is removed or renamed, validation fails with `DNS_PROXY_NOT_FOUND`; ProxiFyre never silently switches to another proxy. The GUI assigns an id such as `proxy-1` to a rule when it is selected as the DNS proxy and the rule has no id, an invalid id, or an id another rule also uses, and it clears the id on a duplicated copy.

### Shared UDP association

UDP DNS of each address family goes through a single SOCKS5 control connection and `UDP ASSOCIATE`, however many processes and source ports send queries. Only queries that arrive while the association is being opened (when the first query arrives, or after it was closed) wait for the SOCKS5 handshake (and, with `TLS` transport, the TLS handshake); after that, queries are sent at once.

- **Matching answers to queries.** While a query is in flight, its DNS message ID is replaced by a unique, randomly chosen ID. The answer carrying that ID is returned to the socket that asked, with the socket's own message ID, but only if it also carries the query's question (name, ignoring case, type and class). A question-less error response from the server is accepted too. A retransmission from the same socket reuses the ID. Up to 4,096 queries can be in flight; a query without an answer is forgotten after 10 seconds. An answer that matches no query in flight, or whose question differs, is dropped. A query whose question section cannot be parsed is dropped.
- **Source of the answer.** The answer is presented as coming from the server Windows queried, whatever source address (IPv4 or IPv6) the SOCKS5 relay reports, because a resolver discards an answer from an address it did not query. RFC 1928 relays report the server that answered (the `serverOverride` server when one is set); some report their own address. This applies with or without a `serverOverride`.
- **Large answers.** An answer that does not fit in one unfragmented 1,280-byte packet is returned truncated, as a DNS server would: the TC bit is set and only the header and question are kept. Windows then repeats the query over TCP through the same proxy. Without this, the reply from ProxiFyre's local listener would be fragmented and could not be delivered.
- **Opening and reopening.** The association is opened when the first query arrives; up to 64 queries wait for it, each for at most 3 seconds (Windows retransmits a query after about a second). It is closed, and reopened on the next query (possibly after a delay, see below), when its control connection closes (TCP keepalive also detects a connection that silently disappeared), its relay socket fails, or it looks silently dead: at least three queries sent after the last datagram from the relay went unanswered, and it has been open for at least 30 seconds. Queries to a resolver that never answers therefore do not close an association that keeps delivering other answers. Queries in flight when the association closes are lost, and Windows retries them.
- **When it cannot be opened.** Queries are dropped, never sent directly. The next attempt waits 1 second, doubling after each failure up to 30 seconds; queries arriving meanwhile are dropped. An association that closes less than 30 seconds after opening, or that is closed because queries stopped being answered, also delays the next attempt. If that association worked (it received anything from the relay and lived at least 5 seconds), the delay restarts at 1 second, so a relay whose UDP path dies on idle, or a server that ends associations early, is retried quickly each time. One that received nothing, or died within seconds, makes the delay grow, so a server that accepts `UDP ASSOCIATE` and then fails is not reconnected in a tight loop and a relay that never answers is retried less and less often. The delay also resets once an association has proved itself: something arrived from the relay after it had been open for 30 seconds, or it closed normally at that age. Queries waiting when a failure starts a backoff are dropped.
- **Logging.** Per address family, the first failure to open an association since an association last received something (or since the service started) is logged as a warning and later failures at `Debug`. Every successful open and every close is logged at `Info` with its reason and, when the next attempt is delayed, the delay. When an association closes after queries were sent through it and nothing ever came back, a warning says so. If 10 seconds or more passed since its first query (or it was closed because queries stopped being answered), the warning says that either the SOCKS5 server's UDP relay does not work or the DNS servers Windows queries cannot be reached from the proxy (a local resolver without a `serverOverride`, for example); if the association ended sooner (its control connection closed or its relay socket failed), it says that instead, with the reason; if the relay socket failed before any query could be sent, it says that. Each of these three warnings is given once until an answer arrives, so one does not hide another. Counts of dropped queries and answers are logged at `Info` at most every 30 seconds, and once more when the service stops.

The local listener accepts a datagram only from a source port from which ProxiFyre redirected a UDP DNS query in the last 30 seconds, never from a loopback address, and only if it names port 53 of the address it came from (the server the client queried) or, with a `serverOverride`, the override. So a local process cannot use it to reach other destinations through the proxy. The listener is bound to all local addresses, like the proxy's other local listeners, so another host that guesses an authorized port could still make the proxy send a DNS query to port 53 of whatever source address its datagram claims, or to the override. It never receives the answer, which is delivered to the local client port. When the service stops, the DNS relays stop while packet filtering is still active and stay known to the filter until it has stopped, so answers they send while stopping never leave the computer; new UDP DNS is dropped meanwhile, without a warning.

### Server override

Without `serverOverride`, each query keeps its original destination: the SOCKS5 server is asked to reach the DNS server Windows queried. That fails when Windows uses a local resolver, such as a home router at `192.168.1.1`, which the remote SOCKS5 server cannot reach. Set `serverOverride` to a resolver that is reachable from the SOCKS5 server, such as `1.1.1.1`.

With an override, only the SOCKS5 destination changes: the `UDP ASSOCIATE` datagram header or the `CONNECT` target names the override, while the packets the application sees keep the original server address. A UDP answer comes back from the override server and is presented as coming from the server the resolver queried (see [Shared UDP association](#shared-udp-association)). Checksums are recalculated on every rewritten packet.

### Examples

Direct (default; equivalent to omitting `dns`):

```json
"dns": { "mode": "Direct" }
```

Proxy through the rule with `"id": "office"`, keeping the original DNS servers:

```json
"dns": { "mode": "Proxy", "proxyId": "office" }
```

Proxy with an IPv4 override for a configuration that uses a router-provided resolver:

```json
"dns": { "mode": "Proxy", "proxyId": "office", "serverOverride": "1.1.1.1" }
```

### Recursion and ProxiFyre's own traffic

SOCKS5 endpoint host names are resolved once while the configuration is loaded, before packet filtering starts, so that lookup is never captured. ProxiFyre's own traffic to a configured SOCKS5 server is never redirected into the DNS proxy, even if it is addressed to port 53, while queries from any other process to a host that is both a SOCKS5 server and a resolver follow the DNS policy like any other query, including `serverOverride`:

- **TCP:** ProxiFyre connects to a SOCKS5 server only on its configured port. A TCP packet to port 53 of a SOCKS5 server is therefore a candidate for ProxiFyre's own traffic only when that server is configured on port 53, and it is exempt only when its sending process is ProxiFyre itself.
- **UDP:** the only ProxiFyre UDP traffic to a SOCKS5 server's address that can reach this check goes to the UDP relay endpoints the server returns for `UDP ASSOCIATE`, both for application UDP and for the DNS proxy's shared association. (Replies from ProxiFyre's local UDP listeners can also be addressed to a SOCKS5 server's host, but they are handled as listener replies before any DNS decision and are never passed.) Unless a server has returned a relay on port 53, no UDP packet to port 53 of a SOCKS5 server can be ProxiFyre's own, so all of them follow the DNS policy with no sender check. Once a relay on port 53 has been seen (logged once at Info), such a packet is exempt only when its sending process is ProxiFyre itself.

When a sender check is needed and the sender cannot be determined, even after the connection table is refreshed, the packet is dropped rather than passed or redirected. Senders that typically cannot be determined include traffic that Windows forwards on behalf of virtual machines or containers (for example through Hyper-V, WSL, or Internet Connection Sharing), which has no owning local process, and sockets owned by the kernel or by drivers rather than by a user-mode process.

The sender is taken from ProxiFyre's cached copy of the Windows connection tables, which is refreshed whenever a packet has to wait for its owner to be resolved, not on a timer. When a sender check is needed, this leaves a narrow residual race: if ProxiFyre closes one of its own sockets and another process reuses the same local port before the cache is next refreshed, that process's query can be treated as ProxiFyre's own and sent directly to the SOCKS5 server's address. The reverse, ProxiFyre's own packet attributed to a stale foreign owner, would send it into the DNS proxy, where it fails rather than leaving the machine directly. The race therefore applies only when a SOCKS5 server is configured on TCP port 53 or returns a UDP relay on port 53, and DNS is addressed to that server's own IP address. To avoid it, do not run a SOCKS5 server or its UDP relay on port 53 while using that server's address as a resolver in `Proxy` mode.

### Limitations

- Only conventional DNS on port 53 is affected. DNS over HTTPS, DNS over TLS, DNS over QUIC, mDNS (5353), and LLMNR (5355) are outside the scope of this feature; applications that resolve names internally over encrypted transports (for example browsers with secure DNS enabled) are routed according to their ordinary application rules.
- ProxiFyre does not change Windows DNS adapter settings, does not disable or reconfigure the DNS Client service, and does not run its own resolver or cache. Answers already cached by Windows before the service started or before `Proxy` mode was enabled are still served from that cache; run `ipconfig /flushdns` after switching modes for an immediate effect.
- Only traffic visible to the Windows Packet Filter layer is captured. Loopback and local resolvers (for example a resolver on `127.0.0.1` or `::1`, or a resolver inside a local VM or container reached through a virtual adapter that is not filtered) are not routed, and their own upstream queries are subject to the same policy only if they leave through a filtered adapter.
- All UDP DNS of one address family leaves the SOCKS5 server's relay from the same source port, so the per-query source port randomization Windows applies does not extend beyond the proxy. Between the SOCKS5 server and the DNS server, forged answers are guarded against by the random 16-bit message ID ProxiFyre assigns (and by the relay, if it accepts answers only from the servers it was asked to reach).
- Queries in flight when the shared UDP association is reopened are lost; Windows retries them.
- When the service is stopped, packet filtering stops and all traffic, including DNS, is direct.
- UDP sent to a broadcast or multicast link-layer address is passed before the DNS policy is applied, as it is for application traffic, so a port-53 datagram addressed to a broadcast or multicast address is not proxied. Conventional DNS is unicast.
- An IPv6 packet whose extension-header chain ProxiFyre cannot walk to a UDP or TCP header (for example one protected by AH or ESP, or a truncated chain) is passed without being classified.
- A proxied TCP connection that stays idle for more than 5 minutes loses its redirect entry. This applies to every proxied TCP connection, not only DNS. If the local proxy then sends first on that connection, its segments are dropped rather than sent to the real server, so the connection stalls until the application or the proxy times it out instead of being reset. A segment the application sends on such a connection is no longer redirected either: for application traffic it goes to the real server as before, which normally resets the connection; for DNS in `Proxy` mode it is dropped.
- Changing DNS settings requires a service restart.

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
