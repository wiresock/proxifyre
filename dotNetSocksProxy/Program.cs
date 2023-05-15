using System;
using System.Linq;
using Socksifier;

namespace dotNetSocksProxy
{
    // Main class for the SOCKS proxy application
    internal class Program
    {
        // Entry point of the application
        private static void Main()
        {
            // Setting the level of logging for the application
            const LogLevel logLevel = LogLevel.None;

            // Define the names of the applications to be proxied
            const string appName1 = "chrome";
            const string appName2 = "firefox";

            // Define the SOCKS5 proxy endpoints, e.g. 158.101.205.51:1080
            const string socks5ProxyEndpoint1 = "PUT-YOUR-SOCKS5-PROXY-ENDPOINT-HERE";
            const string socks5ProxyEndpoint2 = "PUT-YOUR-SOCKS5-PROXY-ENDPOINT-HERE";

            // Define the username and password for the proxy, assumes that both proxies above use the same credentials
            const string username = "PUT-YOUR-SOCKS5-PROXY-USERNAME-HERE";
            const string password = "PUT-YOUR-SOCKS5-PROXY-PASSWORD-HERE";

            // Get an instance of the Socksifier
            var wiresock = Socksifier.Socksifier.GetInstance(logLevel);

            // Attach the LogPrinter method to the LogEvent event
            wiresock.LogEvent += LogPrinter;

            // Set the limit for logging and the interval between logs
            wiresock.LogLimit = 100;
            wiresock.LogEventInterval = 1000;

            // Add the defined SOCKS5 proxies
            var oracle = wiresock.AddSocks5Proxy(socks5ProxyEndpoint1, username, password, true);
            var oracle2 = wiresock.AddSocks5Proxy(socks5ProxyEndpoint2, username, password, true);

            // Associate the defined application names to the proxies
            if (oracle2.ToInt64() != -1 && wiresock.AssociateProcessNameToProxy(appName1, oracle2))
                Console.WriteLine("Successfully associated {0} to SOCKS5 proxy!", appName1);

            if (oracle.ToInt64() != -1 && wiresock.AssociateProcessNameToProxy(appName2, oracle))
                Console.WriteLine("Successfully associated {0} to SOCKS5 proxy!", appName2);

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