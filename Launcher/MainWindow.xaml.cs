using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Diagnostics;
using Microsoft.Win32;
using Path = System.IO.Path;
using System.Threading;
namespace Launcher
{
    /// <summary>
    /// MainWindow.xaml 的交互逻辑
    /// </summary>
    public partial class MainWindow : Window
    {
        private const string UniqueEventName = "SpeedUp_UniqueEventName";
        private const string UniqueMutexName = "SpeedUp_UniqueMutexName";
        private Mutex _mutex;
        public MainWindow()
        {
            bool isNewInstance;
            _mutex = new Mutex(true, UniqueMutexName, out isNewInstance);

            if (!isNewInstance)
            {
                MessageBox.Show("It's running.");
                Environment.Exit(0);
            }
            InitializeComponent();
            try
            {
                // get appdata path
                string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                if (File.Exists(appDataPath + "\\Proxifyre\\SpeedUp.exe"))
                {
                    //Start it and close window
                    Process.Start(appDataPath + "\\Proxifyre\\SpeedUp.exe");
                    Environment.Exit(0);
                    return;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error, Please report it" + ex.Message);
            }

        }
        // 14.0 X86
        public static bool IsVCRedistInstalled(string version, string architecture)
        {
            string registryKey = $@"SOFTWARE\Microsoft\VisualStudio\{version}\VC\Runtimes\{architecture}";
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(registryKey))
            {
                if (key != null)
                {
                    object value = key.GetValue("Installed");

                    if (value != null && (int)value == 1)
                    {
                        object minor = key.GetValue("Minor");//v14.40.33810.00
                        if(minor != null && (int)minor >= 40)
                        {
                            return true;
                        }
                    }
                }
            }
            return false;
        }

        public static async Task InstallVcRTAsync()
        {

            var resourceName = "Launcher.Resource.vc_redist.x86.exe";
            // 从嵌入的资源中提取exe文件
            await Task.Run(() =>
            {
                using (Stream resourceStream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName))
                {
                    if (resourceStream != null)
                    {
                        string tempPath = Path.Combine(Path.GetTempPath(), "vc_redist.x86.exe");
                        using (FileStream fileStream = new FileStream(tempPath, FileMode.Create))
                        {
                            resourceStream.CopyTo(fileStream);
                        }

                        // 使用管理员权限静默安装vc_redist.x86.exe
                        ProcessStartInfo processStartInfo = new ProcessStartInfo(tempPath, $"/quiet /norestart /log \"{tempPath}.install.log\"")
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
                            MessageBox.Show("vc_redis install failed, Error: " + exitCode.ToString());
                            //exit
                            Environment.Exit(0);
                        }
                    }
                }
            });
        }
        private void ExtractEmbeddedZipFile(string resourceName, string outputPath)
        {
            var assembly = Assembly.GetExecutingAssembly();
            using (Stream resourceStream = assembly.GetManifestResourceStream(resourceName))
            {
                if (resourceStream == null)
                {
                    return;
                }

                using (FileStream fileStream = new FileStream(outputPath, FileMode.Create, FileAccess.Write))
                {
                    resourceStream.CopyTo(fileStream);
                }
            }

        }

        private async void Window_Loaded(object sender, RoutedEventArgs e)
        {
            try
            {
                //// if SpeedUp.exe is running
                //if (IsProcessRunning("SpeedUp.exe"))
                //{
                //    // If running, close the current application
                //    MessageBox.Show("加速器已启动, 不要重复打开.");
                //    Environment.Exit(0);
                //    return;
                //}

                string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

                if (!IsVCRedistInstalled("14.0", "x86"))
                {
                    await InstallVcRTAsync();
                }
                // get system temp path
                string tempPath = System.IO.Path.GetTempPath();
                // extract embedded zip file to temp path
                ExtractEmbeddedZipFile("Launcher.Resource.latest.zip", tempPath + "output.zip");

                // extract zip file to appdata path
                ZipFile.ExtractToDirectory(tempPath + "output.zip", appDataPath + "\\Proxifyre");
                if (File.Exists(tempPath + "output.zip"))
                {
                    //delete it
                    File.Delete(tempPath + "output.zip");
                }
                //string zipFilePath = "path/to/your/zipfile.zip";
                //string extractPath = "path/to/extract/folder";
                //ZipFile.ExtractToDirectory(zipFilePath, extractPath);
                if (File.Exists(appDataPath + "\\Proxifyre\\SpeedUp.exe"))
                {
                    //Start it and close window
                    Process.Start(appDataPath + "\\Proxifyre\\SpeedUp.exe");
                    this.Close();
                    return;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error, Please report it: " + ex.Message);
                this.Close();
                return;
            }
        }

        private bool IsProcessRunning(string processName)
        {
            return Process.GetProcessesByName(processName).Any();
        }
    }
}
