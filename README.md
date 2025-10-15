This repo is based on ProxiFyre: SOCKS5 Proxifier for Windows. Appreciate it.

## Changes.
1. Add a windows UI
2. Support ip range so that only connections in that ip range will be forwarded to the proxy
  * Create a config: `app-config.json`
  * Set the content:
```
{
 "logLevel": "Info",
"proxies": [
    {
      "appNames": [ "rdcman", "mstsc" ],
      "socks5ProxyEndpoint": "127.0.0.1:1080",
      "supportedProtocols": [ "TCP" ],
      "ipRanges": [
        "192.168.100.0/24"
      ]
    }
  ]
}
```