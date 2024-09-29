using Socksifier;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using NLog;
using LogLevel = Socksifier.LogLevel;
using NLog.Config;
using System.Reflection;
using System.IO;
using AutoUpdaterDotNET;
using System.Windows.Threading;
using System.Threading;
namespace SpeedUp
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        private Socksifier.Socksifier _socksify;
        private static LogLevel _logLevel;
        private static readonly Logger _logger = LogManager.GetCurrentClassLogger();
        private const string UniqueEventName = "SpeedUp_UniqueEventName";
        private const string UniqueMutexName = "SpeedUp_UniqueMutexName";
        private Mutex _mutex;
        private void ShowLoginWindow()
        {
        }
        protected override async void OnStartup(StartupEventArgs e)
        {
            bool isNewInstance;
            _mutex = new Mutex(true, UniqueMutexName, out isNewInstance);

            if (!isNewInstance)
            {
                MessageBox.Show("It's running.");
                Environment.Exit(0);
            }
            base.OnStartup(e);
            //MessageBox.Show("0");

            // 显示启动画面
            SplashScreen splashScreen = new SplashScreen();
            splashScreen.Show();


            await InitializeApplication();
            var mainWindow = new MainWindow();
            mainWindow.Show();
            // 异步执行初始化操作
            splashScreen.Close();

            //MainWindow mainWindow = new MainWindow();
            //mainWindow.Show();
        }

        protected override void OnExit(ExitEventArgs e)
        {
            _mutex?.ReleaseMutex();
            base.OnExit(e);
        }

        private void Application_LoadCompleted(object sender, System.Windows.Navigation.NavigationEventArgs e)
        {
            //DispatcherTimer timer = new DispatcherTimer { Interval = TimeSpan.FromDays(2) };
            //timer.Tick += delegate
            //{
            //    var url = $"{Services.BaseUrl}/static/version.xml";
            //    AutoUpdater.Start(url);
            //};
            //timer.Start();
        }

        private async Task InitializeApplication()
        {
//#if !DEBUG
//            var url = $"{Services.BaseUrl}/static/version.xml";
//            AutoUpdater.Start(url);
//#endif
            Utils.CreateShortcutToDesktop();
            // Get the current executable path
            var executablePath = Assembly.GetExecutingAssembly().Location;
            var directoryPath = System.IO.Path.GetDirectoryName(executablePath);
            // Form the path to NLog.config
            var logConfigFilePath = System.IO.Path.Combine(directoryPath ?? string.Empty, "NLog.config");
            if (File.Exists(logConfigFilePath))
            {
                LogManager.Configuration = new XmlLoggingConfiguration(logConfigFilePath);
            }

            // Handle the global log level from the configuration
            _logLevel = LogLevel.Info;
            // Get an instance of the Socksifier
            _socksify = Socksifier.Socksifier.GetInstance(_logLevel);

            if (!_socksify.Init())
            {
                await Utils.InstallMSIAsync();
                _socksify.Init();
            }
            // Attach the LogPrinter method to the LogEvent event
            _socksify.LogEvent += LogPrinter;

            // Set the limit for logging and the interval between logs
            _socksify.LogLimit = 100;
            _socksify.LogEventInterval = 1000;
        }
        public async Task Stop()
        {
            await Task.Run(() =>
            {
                _socksify.Stop();
            });
        }
        public void Uinit()
        {
            // Dispose of the Socksifier before exiting
            _socksify.Dispose();
            if (_logLevel != LogLevel.None)
                _logger.Info("ProxiFyre Service has stopped.");
            LogManager.Shutdown();
        }

        private void Application_Exit(object sender, ExitEventArgs e)
        {
            Uinit();
        }

        public async Task Start(AppSettings appSettings)
        {
            // Set the limit for logging and the interval between logs
            _socksify.LogLimit = 100;
            _socksify.LogEventInterval = 1000;
            await Task.Run(() =>
            {
                // Add the defined SOCKS5 proxies
                var proxy = _socksify.AddSocks5Proxy(appSettings.Socks5ProxyEndpoint, appSettings.Username,
                    appSettings.Password, appSettings.SupportedProtocolsParse,
                    true); // Assuming the AddSocks5Proxy method supports a list of protocols
                foreach (var appName in appSettings.AppNames)
                {
                    // Associate the defined application names to the proxies
                    if (proxy.ToInt64() != -1 && _socksify.AssociateProcessNameToProxy(appName, proxy) && _logLevel != LogLevel.None)
                    {
                        //_logger.Info(
                        //    $"Successfully associated {appName} to {appSettings.Socks5ProxyEndpoint} SOCKS5 proxy with protocols {string.Join(", ", appSettings.SupportedProtocols)}!");
                    }
                }
                _socksify.Start();

                // Inform user that the application is running
                if (_logLevel != LogLevel.None)
                    _logger.Info("ProxiFyre Service is running...");

            });
        }
        // Method to handle logging events
        private static void LogPrinter(object sender, LogEventArgs e)
        {
            if (_logLevel == LogLevel.None)
                return;

            // Loop through each log entry and log it using NLog
            foreach (var entry in e.Log.Where(entry => entry != null))
            {
                var logMessage =
                    $"{new DateTime(1970, 1, 1).AddSeconds(entry.TimeStamp / 1000)}::{entry.Event}::{entry.Description}::{entry.Data}";
                _logger.Info(logMessage);
            }
        }
    }
}
