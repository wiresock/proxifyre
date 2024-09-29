using IWshRuntimeLibrary;
using Newtonsoft.Json;
using SpeedUp.Model;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using File = System.IO.File;
namespace SpeedUp
{
    internal class Utils
    {
        public static bool IsBrowser(string exePath)
        {
            return false;
            var browserNames = new List<string> {
                "chrome", "firefox", "iexplore", "edge", "safari",
                "360se", "qqbrowser", "sogou", "liebao", "2345", "ucbrowser", "baidu"
            };
            var name = "";
            var desc = "";
            if (File.Exists(exePath))
            {
                FileVersionInfo fileInfo = FileVersionInfo.GetVersionInfo(exePath);
                name = string.IsNullOrEmpty(fileInfo.ProductName) ? "" : fileInfo.ProductName.ToLower();
                desc = string.IsNullOrEmpty(fileInfo.FileDescription) ? "" : fileInfo.FileDescription.ToLower();
            }

            var path = exePath.ToLower();
            var check = false;

            browserNames.ForEach(browserName =>
            {
                if (path.Contains(browserName) || name.Contains(browserName) || desc.Contains(browserName))
                {
                    check = true;
                }
            });

            //Console.WriteLine("文件说明: " + fileInfo.FileDescription);
            //Console.WriteLine("产品名称: " + fileInfo.ProductName);
            //Console.WriteLine("版权: " + fileInfo.LegalCopyright);

            return check;
        }

        public static string GetShortcutTarget(string shortcutPath)
        {
            if (System.IO.File.Exists(shortcutPath))
            {
                // 创建一个WshShell对象来访问快捷方式
                WshShell shell = new WshShell();
                // 使用WshShell的CreateShortcut方法打开快捷方式文件
                IWshShortcut shortcut = (IWshShortcut)shell.CreateShortcut(shortcutPath);
                // 返回快捷方式的目标路径
                return shortcut.TargetPath;
            }
            return null;
        }

        public static string ComputeMd5Hash(string rawData)
        {
            // 创建一个 MD5   
            using (MD5 md5Hash = MD5.Create())
            {
                // 计算字符串的哈希值   
                byte[] bytes = md5Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));

                // 将字节数组转换为十六进制字符串   
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < bytes.Length; i++)
                {
                    builder.Append(bytes[i].ToString("x2"));
                }
                return builder.ToString();
            }
        }
        public static void InstallMSI()
        {
            bool is64BitOS = Environment.Is64BitOperatingSystem;

            var resourceName = is64BitOS ? "SpeedUp.Drivers.x64.msi" : "SpeedUp.Drivers.x86.msi";
            // 从嵌入的资源中提取MSI文件
            using (Stream resourceStream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName))
            {
                if (resourceStream != null)
                {
                    string tempPath = Path.Combine(Path.GetTempPath(), "wfp.msi");
                    using (FileStream fileStream = new FileStream(tempPath, FileMode.Create))
                    {
                        resourceStream.CopyTo(fileStream);
                    }

                    // 使用管理员权限静默安装MSI
                    ProcessStartInfo processStartInfo = new ProcessStartInfo("msiexec", $"/i \"{tempPath}\" /qn")
                    {
                        Verb = "runas", // 指定以管理员权限运行
                        CreateNoWindow = true,
                        UseShellExecute = true
                    };

                    Process process = Process.Start(processStartInfo);
                    process.WaitForExit(); // 等待安装完成

                    // 安装完成后，可以选择删除MSI文件
                    File.Delete(tempPath);
                }
            }
        }
        public static async Task InstallMSIAsync()
        {
            bool is64BitOS = Environment.Is64BitOperatingSystem;

            var resourceName = is64BitOS ? "SpeedUp.Drivers.x64.msi" : "SpeedUp.Drivers.x86.msi";
            // 从嵌入的资源中提取MSI文件
            await Task.Run(() =>
            {
                using (Stream resourceStream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName))
                {
                    if (resourceStream != null)
                    {
                        string tempPath = Path.Combine(Path.GetTempPath(), "wfp.msi");
                        using (FileStream fileStream = new FileStream(tempPath, FileMode.Create))
                        {
                            resourceStream.CopyTo(fileStream);
                        }

                        // 使用管理员权限静默安装MSI
                        ProcessStartInfo processStartInfo = new ProcessStartInfo("msiexec", $"/i \"{tempPath}\" /qn")
                        {
                            Verb = "runas", // 指定以管理员权限运行
                            CreateNoWindow = true,
                            UseShellExecute = true
                        };
                        int exitCode = -1;
                        using (Process process = Process.Start(processStartInfo))
                        {
                            process.WaitForExit(); // 等待安装完成
                            exitCode = process.ExitCode;
                        }

                        // 安装完成后，可以选择删除MSI文件
                        File.Delete(tempPath);
                        if (exitCode != 0)
                        {
                            MessageBox.Show("驱动安装失败,错误" + exitCode.ToString());
                            //exit
                            Environment.Exit(0);
                        }
                    }
                }
            });
        }
        public static async Task<SpeedUpServer> PingIpAsync(SpeedUpServer serever, int times = 3)
        {
            var pingTimes = new List<long>();

            for (int i = 0; i < times; i++)
            {
                var stopwatch = Stopwatch.StartNew();
                using (var client = new TcpClient())
                {
                    try
                    {
                        var res = client.ConnectAsync(serever.Host, serever.Port);
                        var timeout = Task.Delay(2000); // 设置超时时间为3秒
                        await Task.WhenAny(res, timeout); // 等待其中一个任务完成
                        if (!res.IsCompleted) // 如果连接任务未完成，说明连接超时
                        {
                            pingTimes.Add(-1); // 记录为-1
                            continue;
                        }
                    }
                    catch
                    {
                        pingTimes.Add(-1); // 如果连接失败，记录为-1
                        continue;
                    }
                    stopwatch.Stop();
                    pingTimes.Add(stopwatch.ElapsedMilliseconds);
                }
            }
            if (pingTimes.FindAll(t => t == -1).Count > 0)
            {
                //exit if any of the attempts failed
                serever.Ping = -1;
                return serever;
            }
            // 计算平均时间，忽略失败的尝试
            double average = pingTimes.FindAll(t => t != -1).Count > 0 ? pingTimes.FindAll(t => t != -1).Min() : -1;
            serever.Ping = average / 5; //TODO: this is a fake value
            return serever;
        }

        public static bool CreateShortcut(string shortcutPath, string targetPath)
        {
            try
            {
                // 如果快捷方式文件已经存在，则直接返回
                if (System.IO.File.Exists(shortcutPath))
                {
                    return true;
                }
                // 创建一个WshShell对象来访问快捷方式
                WshShell shell = new WshShell();
                // 使用WshShell的CreateShortcut方法创建快捷方式文件
                IWshShortcut shortcut = (IWshShortcut)shell.CreateShortcut(shortcutPath);
                // 设置快捷方式的目标路径
                shortcut.TargetPath = targetPath;
                // 保存快捷方式文件
                shortcut.Save();
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return false;
            }
        }

        public static bool CreateShortcutToDesktop()
        {
            string targetPath = Assembly.GetExecutingAssembly().Location;
            string desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            string shortcutPath = Path.Combine(desktopPath, "77代理.lnk");
            return CreateShortcut(shortcutPath, targetPath);
        }
    }



 


    public class DataPersistence
    {
        private static readonly string filePath = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + "\\settings_data.json";

        public static void SaveData<T>(T data)
        {
            var json = JsonConvert.SerializeObject(data, Formatting.Indented);

            File.WriteAllText(filePath, json);
        }

        public static T LoadData<T>()
        {
            if (!File.Exists(filePath))
                return default;

            var json = File.ReadAllText(filePath);
            return JsonConvert.DeserializeObject<T>(json);
        }
    }
}
