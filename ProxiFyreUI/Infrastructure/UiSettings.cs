using ProxiFyre.Configuration;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Web.Script.Serialization;

namespace ProxiFyreUI.Infrastructure
{
    public sealed class UiSettings
    {
        public string SelectedEnginePath { get; set; }

        public bool MinimizeToTray { get; set; } = true;

        public bool FollowLogs { get; set; } = true;
    }

    public sealed class UiSettingsStore
    {
        private readonly string _path;

        public UiSettingsStore(string path = null)
        {
            _path = path ?? ProxiFyrePaths.GetUiSettingsPath();
        }

        public string Path => _path;

        public UiSettings Load()
        {
            try
            {
                if (!File.Exists(_path))
                    return new UiSettings();

                var json = File.ReadAllText(_path, Encoding.UTF8);
                var values = new JavaScriptSerializer()
                    .Deserialize<Dictionary<string, object>>(json);
                if (values == null)
                    return new UiSettings();

                var settings = new UiSettings();
                object value;
                if (values.TryGetValue("selectedEnginePath", out value))
                    settings.SelectedEnginePath = value as string;
                if (values.TryGetValue("minimizeToTray", out value) && value is bool)
                    settings.MinimizeToTray = (bool)value;
                if (values.TryGetValue("followLogs", out value) && value is bool)
                    settings.FollowLogs = (bool)value;
                return settings;
            }
            catch (IOException)
            {
                return new UiSettings();
            }
            catch (UnauthorizedAccessException)
            {
                return new UiSettings();
            }
            catch (ArgumentException)
            {
                return new UiSettings();
            }
            catch (InvalidOperationException)
            {
                return new UiSettings();
            }
        }

        public void Save(UiSettings settings)
        {
            if (settings == null)
                throw new ArgumentNullException(nameof(settings));

            var directory = System.IO.Path.GetDirectoryName(_path);
            if (string.IsNullOrWhiteSpace(directory))
                throw new InvalidOperationException("The UI settings path has no parent directory.");

            Directory.CreateDirectory(directory);
            var temporaryPath = _path + ".tmp";
            var json = new JavaScriptSerializer().Serialize(new Dictionary<string, object>
            {
                { "selectedEnginePath", settings.SelectedEnginePath },
                { "minimizeToTray", settings.MinimizeToTray },
                { "followLogs", settings.FollowLogs }
            });

            try
            {
                using (var stream = new FileStream(temporaryPath, FileMode.Create, FileAccess.Write, FileShare.None))
                using (var writer = new StreamWriter(stream, new UTF8Encoding(false)))
                {
                    writer.Write(json);
                    writer.Flush();
                    stream.Flush(true);
                }

                if (File.Exists(_path))
                {
                    try
                    {
                        File.Replace(temporaryPath, _path, null, true);
                    }
                    catch (PlatformNotSupportedException)
                    {
                        File.Delete(_path);
                        File.Move(temporaryPath, _path);
                    }
                }
                else
                {
                    File.Move(temporaryPath, _path);
                }
            }
            finally
            {
                if (File.Exists(temporaryPath))
                {
                    try { File.Delete(temporaryPath); }
                    catch (IOException) { }
                    catch (UnauthorizedAccessException) { }
                }
            }
        }
    }
}
