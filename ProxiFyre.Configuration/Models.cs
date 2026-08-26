using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;

namespace ProxiFyre.Configuration
{
    /// <summary>
    /// The complete engine configuration stored in app-config.json.
    /// </summary>
    public sealed class ProxiFyreConfiguration
    {
        public ProxiFyreConfiguration()
        {
            LogLevel = "Info";
            Proxies = new List<ProxyRule>();
            Excludes = new List<string>();
            ExtensionData = new Dictionary<string, JToken>(StringComparer.Ordinal);
        }

        [JsonProperty("logLevel")]
        public string LogLevel { get; set; }

        [JsonProperty("bypassLan")]
        public bool BypassLan { get; set; }

        [JsonProperty("proxies")]
        public List<ProxyRule> Proxies { get; set; }

        [JsonProperty("excludes")]
        public List<string> Excludes { get; set; }

        [JsonExtensionData]
        public IDictionary<string, JToken> ExtensionData { get; set; }

        /// <summary>
        /// Creates the blank model used when neither a live nor a sample file exists.
        /// </summary>
        public static ProxiFyreConfiguration CreateBlank()
        {
            return new ProxiFyreConfiguration();
        }
    }

    /// <summary>
    /// One ordered application-to-proxy routing rule.
    /// </summary>
    public sealed class ProxyRule
    {
        public ProxyRule()
        {
            AppNames = new List<string>();
            ExtensionData = new Dictionary<string, JToken>(StringComparer.Ordinal);
        }

        [JsonProperty("appNames")]
        public List<string> AppNames { get; set; }

        [JsonProperty("socks5ProxyEndpoint", NullValueHandling = NullValueHandling.Ignore)]
        public string Socks5ProxyEndpoint { get; set; }

        [JsonProperty("username", NullValueHandling = NullValueHandling.Ignore)]
        public string Username { get; set; }

        [JsonProperty("password", NullValueHandling = NullValueHandling.Ignore)]
        public string Password { get; set; }

        [JsonProperty("socks5Transport", NullValueHandling = NullValueHandling.Ignore)]
        public string Socks5Transport { get; set; }

        [JsonProperty("tlsServerName", NullValueHandling = NullValueHandling.Ignore)]
        public string TlsServerName { get; set; }

        [JsonProperty("tlsPinnedSha256", NullValueHandling = NullValueHandling.Ignore)]
        public string TlsPinnedSha256 { get; set; }

        [JsonProperty("tlsAllowInvalidCertificate")]
        public bool TlsAllowInvalidCertificate { get; set; }

        [JsonProperty("supportedProtocols", NullValueHandling = NullValueHandling.Ignore)]
        public List<string> SupportedProtocols { get; set; }

        [JsonProperty("supportedAddressFamilies", NullValueHandling = NullValueHandling.Ignore)]
        public List<string> SupportedAddressFamilies { get; set; }

        [JsonExtensionData]
        public IDictionary<string, JToken> ExtensionData { get; set; }

        /// <summary>
        /// Gets the explicitly configured TLS name, or the endpoint host when it is omitted.
        /// </summary>
        [JsonIgnore]
        public string EffectiveTlsServerName
        {
            get
            {
                return string.IsNullOrWhiteSpace(TlsServerName)
                    ? EndpointParser.ExtractHost(Socks5ProxyEndpoint)
                    : TlsServerName.Trim();
            }
        }
    }
}
