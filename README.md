# Based on ProxiFyre: SOCKS5 Proxifier for Windows

# Add a windows UI

# Support ip range so that only connections in that ip range will be forwarded to the proxy
1. Create a config: `app-config.json`
2. Set the content:
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