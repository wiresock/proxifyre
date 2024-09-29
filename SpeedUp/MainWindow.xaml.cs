using SpeedUp.Model;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices.ComTypes;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Forms;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Windows.Threading;
using static System.Windows.Forms.VisualStyles.VisualStyleElement.TrackBar;

namespace SpeedUp
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {

        public void ShowToast(string message)
        {
            var duration = TimeSpan.FromSeconds(1.5);
            ToastText.Text = message;
            ToastPopup.IsOpen = true;

            DispatcherTimer timer = new DispatcherTimer
            {
                Interval = duration
            };
            timer.Tick += (s, args) =>
            {
                ToastPopup.IsOpen = false;
                timer.Stop();
            };
            timer.Start();
        }

        private NotifyIcon notifyIcon;
        public MainWindow()
        {
            InitializeComponent();
            // 初始化NotifyIcon
            notifyIcon = new NotifyIcon
            {

                Icon = LoadIconFromResource("SpeedUp.icons.icon.ico"), // 设置托盘图标的路径
                Visible = false, // 初始时不显示
                Text = "Double click to open" // 鼠标悬停时的文本
            };

            notifyIcon.MouseDoubleClick += NotifyIcon_MouseDoubleClick;

        }
        private Icon LoadIconFromResource(string resourceName)
        {
            var assembly = Assembly.GetExecutingAssembly();
            using (Stream stream = assembly.GetManifestResourceStream(resourceName))
            {
                if (stream == null)
                {
                    throw new FileNotFoundException("Could not find embedded resource", resourceName);
                }
                return new Icon(stream);
            }
        }
        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        private void MinusButton_Click(object sender, RoutedEventArgs e)
        {
            Console.WriteLine("Minimize");
            this.WindowState = WindowState.Minimized;
        }


        private void Grid_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            // 检查是否为左键点击
            if (e.LeftButton == MouseButtonState.Pressed)
            {
                // 拖动窗口
                DragMove();
            }
        }

        private void Window_StateChanged(object sender, EventArgs e)
        {
            // 当窗口最小化时隐藏任务栏图标并显示托盘图标
            if (WindowState == WindowState.Minimized)
            {
                Hide();
                notifyIcon.Visible = true;
            }
        }

        private void NotifyIcon_MouseDoubleClick(object sender, System.Windows.Forms.MouseEventArgs e)
        {
            // 双击托盘图标时恢复窗口
            Show();
            WindowState = WindowState.Normal;
            notifyIcon.Visible = false;
        }

        private async void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            if (GlobalData.IsRunning)
            {
                if (System.Windows.Application.Current is App app)
                {
                    SwitchButton.Content = "Stopping...";
                    StartButton.IsEnabled = false;
                    await app.Stop();
                    StartButton.IsEnabled = true;
                    GlobalData.IsRunning = false;
                    SwitchButton.Content = "Start";
                    if (MainFrame.Content is Frames.SpeedUpPage speedUpPage)
                    {
                        speedUpPage.StopAcceleration();
                    }
                }
            }
            // 清理，避免托盘图标残留
            notifyIcon.Dispose();
            System.Windows.Application.Current.Shutdown();
        }

        private async void StartButton_Click(object sender, RoutedEventArgs e)
        {

            if (MainFrame.Content is Frames.NodeSelectPage nodeSelectPage)
            {
                MainFrame.Content = new Frames.SpeedUpPage();
                NodeSelectButtonLabel.Content = "Nodes";
            }

            if (SettingsHelper.Instance.Settings.FilePaths.Count == 0)
            {
                ShowToast("Please add a executable file!");
                return;
            }
            if (GlobalData.IsRunning)
            {
                if (System.Windows.Application.Current is App app)
                {
                    SwitchButton.Content = "Stopping...";
                    StartButton.IsEnabled = false;
                    await app.Stop();
                    StartButton.IsEnabled = true;
                    GlobalData.IsRunning = false;
                    SwitchButton.Content = "Start";
                    if (MainFrame.Content is Frames.SpeedUpPage speedUpPage)
                    {
                        speedUpPage.StopAcceleration();
                    }
                }
            }
            else
            {
                if (GlobalData.SelectedServerInfo == null)
                {
                    ShowToast("Please select a node");
                    return;
                }

                if (System.Windows.Application.Current is App app)
                {
                    AppSettings appSettings = new AppSettings
                    {
                        AppNames = SettingsHelper.Instance.Settings.FilePaths,
                        SupportedProtocols = new List<string> { "TCP", "UDP" },
                        Socks5ProxyEndpoint = GlobalData.SelectedServerInfo.Host + ":" + GlobalData.SelectedServerInfo.Port.ToString(),
                        Username = GlobalData.SelectedServerInfo.Username,
                        Password = GlobalData.SelectedServerInfo.Secret, //todo: update from current select server info
                    };
                    SwitchButton.Content = "Starting...";
                    StartButton.IsEnabled = false;
                    await app.Start(appSettings);
                    GlobalData.IsRunning = true;
                    StartButton.IsEnabled = true;
                    SwitchButton.Content = "Stop";
                    if (MainFrame.Content is Frames.SpeedUpPage speedUpPage)
                    {
                        speedUpPage.StartAcceleration();
                    }

                }
            }
        }

        private void AddApplicationButton_Click(object sender, RoutedEventArgs e)
        {
            if (GlobalData.IsRunning)
            {
                ShowToast("Please stop proxy first!");
                return;
            }
            //打开文件选择器
            OpenFileDialog openFileDialog = new OpenFileDialog
            {
                Filter = "Executable Files|*.exe|Shortcut Files|*.lnk",
                Multiselect = true
            };
            if (openFileDialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            {
                foreach (string file in openFileDialog.FileNames)
                {
                    if (MainFrame.Content is Frames.SpeedUpPage speedUpPage)
                    {
                        if (!speedUpPage.AddApplication(file))
                        {
                            return;
                        }
                    }
                }
            }
        }

        private void RemoveApplicationButton_Click(object sender, RoutedEventArgs e)
        {
            if (GlobalData.IsRunning)
            {
                ShowToast("Please stop proxy first!");
                return;
            }
            if (MainFrame.Content is Frames.SpeedUpPage speedUpPage)
            {
                speedUpPage.RemoveSelectedApplication();
            }
        }

        private void RunApplicationButton_Click(object sender, RoutedEventArgs e)
        {
            if (MainFrame.Content is Frames.SpeedUpPage speedUpPage)
            {
                speedUpPage.RunSelectedApplication();
            }
        }

        private void NodeSelectButton_Click(object sender, RoutedEventArgs e)
        {
            if (GlobalData.IsRunning)
            {
                ShowToast("Please stop proxy first!");
                return;
            }
            if (MainFrame.Content is Frames.SpeedUpPage speedUpPage)
            {
                MainFrame.Content = new Frames.NodeSelectPage();
                NodeSelectButtonLabel.Content = "Return";
            }
            else
            {
                MainFrame.Content = new Frames.SpeedUpPage();
                NodeSelectButtonLabel.Content = "Nodes";
            }
        }

        private async void Window_LoadedAsync(object sender, RoutedEventArgs e)
        {
            GlobalData.ServerInfos= SettingsHelper.Instance.Settings.ServerList;
            var tasks = new List<Task<SpeedUpServer>>();

            foreach (var server in GlobalData.ServerInfos)
            {
                tasks.Add(Utils.PingIpAsync(server, 3)); // 对每个IP进行3次Ping测试，并计算平均值
            }
            var results = await Task.WhenAll(tasks);
            var bestServer = results.Where(x => x.Ping > 0).OrderBy(x => x.Ping).FirstOrDefault();
            if (bestServer != null)
            {
                bestServer.IsBest = true;
                GlobalData.BestServer = bestServer;
                GlobalData.SelectedServerInfo = bestServer;
            }
            GlobalData.ServerInfos = results.ToList();
            // 隐藏加载界面
            loadingOverlay.Visibility = Visibility.Collapsed;
            if (MainFrame.Content is Frames.SpeedUpPage speedUpPage)
            {
                speedUpPage.NodeName_Text.Text = bestServer.Name;
                speedUpPage.Ping_Text.Text = bestServer.Ping.ToString();
            }
        }
    }
}
