using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.IO;
using System.Linq;
using System.Text;

namespace ProxiFyre.Configuration
{
    public sealed class ConfigurationFormatException : FormatException
    {
        public ConfigurationFormatException(string message, Exception innerException = null)
            : base(message, innerException)
        {
        }
    }

    public interface IConfigurationSerializer
    {
        string Serialize(ProxiFyreConfiguration configuration);

        ProxiFyreConfiguration Deserialize(string json);
    }

    /// <summary>
    /// Serializes the stable JSON schema while retaining extension data from newer engines.
    /// </summary>
    public sealed class ConfigurationSerializer : IConfigurationSerializer
    {
        private static readonly UTF8Encoding Utf8WithoutBom = new UTF8Encoding(false, true);
        private readonly JsonSerializerSettings _settings;

        public ConfigurationSerializer()
        {
            _settings = new JsonSerializerSettings
            {
                Formatting = Formatting.Indented,
                MissingMemberHandling = MissingMemberHandling.Ignore,
                DateParseHandling = DateParseHandling.None,
                Culture = System.Globalization.CultureInfo.InvariantCulture
            };
        }

        public string Serialize(ProxiFyreConfiguration configuration)
        {
            if (configuration == null)
                throw new ArgumentNullException(nameof(configuration));

            return JsonConvert.SerializeObject(configuration, _settings);
        }

        public ProxiFyreConfiguration Deserialize(string json)
        {
            if (json == null)
                throw new ArgumentNullException(nameof(json));

            JObject root;
            try
            {
                root = JObject.Parse(json);
            }
            catch (JsonException ex)
            {
                throw new ConfigurationFormatException(
                    "The configuration is not a valid JSON object.", ex);
            }

            ProxiFyreConfiguration configuration;
            try
            {
                configuration = root.ToObject<ProxiFyreConfiguration>(JsonSerializer.Create(_settings));
            }
            catch (JsonException ex)
            {
                throw new ConfigurationFormatException(
                    "The configuration contains an invalid property value.", ex);
            }
            if (configuration == null)
                throw new ConfigurationFormatException("The configuration contains no settings.");

            // A constructor-created empty list is useful to GUI callers, but the validator must
            // still distinguish an omitted required proxies property from an explicit empty one.
            if (!root.Properties().Any(p => string.Equals(p.Name, "proxies", StringComparison.OrdinalIgnoreCase)))
                configuration.Proxies = null;

            if (configuration.Excludes == null)
                configuration.Excludes = new System.Collections.Generic.List<string>();
            if (configuration.ExtensionData == null)
                configuration.ExtensionData = new System.Collections.Generic.Dictionary<string, JToken>(StringComparer.Ordinal);

            return configuration;
        }

        /// <summary>
        /// Creates a lossless editable copy, including credentials and unknown extension fields.
        /// Keeping this operation here prevents UI projects from taking a direct JSON dependency.
        /// </summary>
        public ProxyRule CloneRule(ProxyRule rule)
        {
            if (rule == null)
                throw new ArgumentNullException(nameof(rule));

            try
            {
                var json = JsonConvert.SerializeObject(rule, _settings);
                var clone = JsonConvert.DeserializeObject<ProxyRule>(json, _settings);
                if (clone == null)
                    throw new ConfigurationFormatException("The proxy rule could not be cloned.");
                return clone;
            }
            catch (JsonException ex)
            {
                throw new ConfigurationFormatException("The proxy rule could not be cloned.", ex);
            }
        }

        public ProxiFyreConfiguration Load(string filePath)
        {
            if (filePath == null)
                throw new ArgumentNullException(nameof(filePath));

            using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var reader = new StreamReader(stream, Utf8WithoutBom, true))
                return Deserialize(reader.ReadToEnd());
        }

        public void Save(string filePath, ProxiFyreConfiguration configuration)
        {
            if (filePath == null)
                throw new ArgumentNullException(nameof(filePath));

            var json = Serialize(configuration);
            using (var stream = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None))
            using (var writer = new StreamWriter(stream, Utf8WithoutBom))
            {
                writer.Write(json);
                writer.Flush();
                stream.Flush(true);
            }
        }

        internal static string DecodeUtf8(byte[] bytes)
        {
            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes));

            var offset = bytes.Length >= 3 && bytes[0] == 0xef && bytes[1] == 0xbb && bytes[2] == 0xbf
                ? 3
                : 0;
            return Utf8WithoutBom.GetString(bytes, offset, bytes.Length - offset);
        }
    }
}
