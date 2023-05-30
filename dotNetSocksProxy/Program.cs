using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Newtonsoft.Json;
using Socksifier;

namespace dotNetSocksProxy
{
    // Main class for the SOCKS proxy application
    internal class Program
    {
        //[
        //{
        //    "appNames": ["chrome", "chrome_canary"],
        //    "socks5ProxyEndpoint": "158.101.205.51:1080",
        //    "username": "username1",
        //    "password": "password1"
        //},
        //{
        //    "appNames": ["firefox", "firefox_dev"],
        //    "socks5ProxyEndpoint": "159.101.205.52:1080",
        //    "username": "username2",
        //    "password": "password2"
        //}
        //]

        private class AppSettings
        {
            public List<string> AppNames { get; set; }
            public string Socks5ProxyEndpoint { get; set; }
            public string Username { get; set; }
            public string Password { get; set; }
        }

        // Entry point of the application
        private static void Main()
        {
            // Setting the level of logging for the application
            const LogLevel logLevel = LogLevel.None;

            // Load the configuration from JSON
            var appSettingsList = JsonConvert.DeserializeObject<List<AppSettings>>(File.ReadAllText("app-config.json"));

            // Get an instance of the Socksifier
            var wiresock = Socksifier.Socksifier.GetInstance(logLevel);

            // Attach the LogPrinter method to the LogEvent event
            wiresock.LogEvent += LogPrinter;

            // Set the limit for logging and the interval between logs
            wiresock.LogLimit = 100;
            wiresock.LogEventInterval = 1000;

            foreach (var appSettings in appSettingsList)
            {
                // Add the defined SOCKS5 proxies
                var oracle = wiresock.AddSocks5Proxy(appSettings.Socks5ProxyEndpoint, appSettings.Username,
                    appSettings.Password, true);

                foreach (var appName in appSettings.AppNames)
                    // Associate the defined application names to the proxies
                    if (oracle.ToInt64() != -1 && wiresock.AssociateProcessNameToProxy(appName, oracle))
                        Console.WriteLine($"Successfully associated {appName} to {appSettings.Socks5ProxyEndpoint} SOCKS5 proxy!");
            }

            // Start the Socksifier, if it fails, dispose and exit
            if (!wiresock.Start())
            {
                Console.WriteLine("Failed to start SOCKS PROXY!");
                wiresock.Dispose();
                return;
            }

            // Inform user that the application is running and how to stop it
            Console.WriteLine("Press any key to stop");

            // Wait for a key press before disposing and exiting
            Console.ReadKey();

            // Dispose of the Socksifier before exiting
            wiresock.Dispose();
        }

        // Method to handle logging events
        private static void LogPrinter(object sender, LogEventArgs e)
        {
            // Loop through each log entry and print it to the console
            foreach (var entry in e.Log.Where(entry => entry != null))
                Console.WriteLine(
                    // ReSharper disable once PossibleLossOfFraction
                    $"{new DateTime(1970, 1, 1).AddSeconds(entry.TimeStamp / 1000)}::{entry.Event}::{entry.Description}::{entry.Data}");
        }
    }
}