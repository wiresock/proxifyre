using System;
using System.IO;
using Newtonsoft.Json;

namespace ProxiFyre.Tests
{
    class ConfigTest
    {
        static void Main(string[] args)
        {
            var jsonConfig = @"{
  ""logLevel"": ""Info"",
  ""blockIPv6"": true,
  ""proxies"": [
    {
      ""appNames"": [""discord""],
      ""socks5ProxyEndpoint"": ""proxy.example.com:1080"",
      ""username"": ""test"",
      ""password"": ""test"",
      ""supportedProtocols"": [""TCP"", ""UDP""]
    }
  ],
  ""excludes"": [""notepad.exe""]
}";

            try
            {
                // This simulates the same deserialization that happens in Program.cs
                var settings = JsonConvert.DeserializeObject<TestProxiFyreSettings>(jsonConfig);
                
                Console.WriteLine($""LogLevel: {settings.LogLevel}"");
                Console.WriteLine($""BlockIPv6: {settings.BlockIPv6}"");
                Console.WriteLine($""Proxies count: {settings.Proxies.Count}"");
                Console.WriteLine($""Excludes count: {settings.ExcludedList.Count}"");
                
                Console.WriteLine(""Configuration parsed successfully!"");
            }
            catch (Exception e)
            {
                Console.WriteLine($""Error parsing configuration: {e.Message}"");
            }
        }
    }
    
    // Test class that mirrors the structure in Program.cs
    public class TestProxiFyreSettings
    {
        public string LogLevel { get; set; }
        
        [JsonProperty(""blockIPv6"", NullValueHandling = NullValueHandling.Ignore)]
        public bool BlockIPv6 { get; set; }
        
        public System.Collections.Generic.List<TestAppSettings> Proxies { get; set; }
        
        [JsonProperty(""excludes"", NullValueHandling = NullValueHandling.Ignore)]
        public System.Collections.Generic.List<string> ExcludedList { get; set; }
    }
    
    public class TestAppSettings
    {
        public System.Collections.Generic.List<string> AppNames { get; set; }
        public string Socks5ProxyEndpoint { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public System.Collections.Generic.List<string> SupportedProtocols { get; set; }
    }
}