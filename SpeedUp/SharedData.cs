using Socksifier;
using SpeedUp.Model;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SpeedUp
{

    internal class ServerInfo
    {
        public long Id { get; set; }
        public int AreaCode { get; set; } //行政代码
        public string Province { get; set; }
        public string City { get; set; }
        public bool Enabled { get; set; }
        public string Name { get; set; }
        public string Host { get; set; }
        public short Port { get; set; }
        public string Secret { get; set; }
        public int Type { get; set; }
        public string Description { get; set; }
        public DateTime? CreationDate { get; set; }
        public DateTime? ModificationDate { get; set; }
    }


    internal static class GlobalData
    {
        private static readonly object lockObject = new object();
        public static string Token { get; set; } = "";
        //public static List<string> FilePaths { get; set; } = new List<string>();
        public static List<SpeedUpServer> ServerInfos { get; set; } = new List<SpeedUpServer>();
        private static SpeedUpServer _selectedServerInfo = null;
        private static SpeedUpServer _bestServer = null;
        public static SpeedUpServer SelectedServerInfo
        {
            get
            {
                lock (lockObject)
                {
                    return _selectedServerInfo;
                }
            }
            set
            {
                lock (lockObject)
                {
                    _selectedServerInfo = value;
                }
            }
        }

        public static SpeedUpServer BestServer
        {
            get
            {
                lock (lockObject)
                {
                    return _bestServer;
                }
            }
            set
            {
                lock (lockObject)
                {
                    _bestServer = value;
                }
            }
        }
        public static volatile bool IsRunning = false;
        public static string CurrentPage { get; set; } = "SpeedUpPage";
    }

    internal class Constants
    {
        public const string FreeNumber = "13888888888";
        public const string FreeUserName = "77daili.com";
    }

    internal class SharedData : INotifyPropertyChanged
    {

        public List<string> FilePaths { get; set; }

        public List<ServerInfo> ServerInfos { get; set; }
        public void AddFilePathsItem(string path)
        {
            FilePaths.Add(path);
            OnPropertyChanged(nameof(FilePaths));
        }

        public void RemoveFilePathItem(string path)
        {
            FilePaths.Remove(path);
            OnPropertyChanged(nameof(FilePaths));
        }

        public string RemoveFilePathItem(int index)
        {
            string path = FilePaths[index];
            FilePaths.RemoveAt(index);
            OnPropertyChanged(nameof(FilePaths));
            return path;
        }


        public List<string> strings { get; set; }
        public string SharedData1
        {
            get { return SharedData1; }
            set
            {
                SharedData1 = value;
                OnPropertyChanged(nameof(SharedData1));
            }
        }

        public event PropertyChangedEventHandler PropertyChanged;

        protected void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }

    public class AppSettings
    {
        public List<string> AppNames { get; set; }
        public string Socks5ProxyEndpoint { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public List<string> SupportedProtocols { get; set; } // Keep the original list for parsing

        public SupportedProtocolsEnum SupportedProtocolsParse // New property for the enum
        {
            get
            {
                if (SupportedProtocols.Count == 0 ||
                    (SupportedProtocols.Contains("TCP") && SupportedProtocols.Contains("UDP")))
                    return SupportedProtocolsEnum.BOTH;
                if (SupportedProtocols.Contains("TCP"))
                    return SupportedProtocolsEnum.TCP;
                return SupportedProtocols.Contains("UDP")
                    ? SupportedProtocolsEnum.UDP
                    : SupportedProtocolsEnum.BOTH;
            }
        }
    }
}
