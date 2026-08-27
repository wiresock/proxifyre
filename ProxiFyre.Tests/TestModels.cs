using ProxiFyre.Configuration;
using System.Collections.Generic;

namespace ProxiFyre.Tests
{
    internal static class TestModels
    {
        public static ProxiFyreConfiguration ValidConfiguration()
        {
            return new ProxiFyreConfiguration
            {
                LogLevel = "Info",
                Proxies = new List<ProxyRule> { ValidRule() },
                Excludes = new List<string>()
            };
        }

        public static ProxyRule ValidRule()
        {
            return new ProxyRule
            {
                AppNames = new List<string> { "browser" },
                Socks5ProxyEndpoint = "proxy.example.com:1080",
                Socks5Transport = "TCP",
                SupportedProtocols = new List<string> { "TCP", "UDP" },
                SupportedAddressFamilies = new List<string> { "IPv4", "IPv6" }
            };
        }
    }
}
