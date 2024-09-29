using SpeedUp.Model;
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

namespace SpeedUp.Frames
{
    public class TreeNode
    {
        public string Name { get; set; }
        public List<TreeNode> Children { get; set; }

        public SpeedUpServer Server { get; set; }
        public TreeNode(string name, SpeedUpServer server = null)
        {
            Name = name;
            Children = new List<TreeNode>();
            Server = server;
        }
    }
    /// <summary>
    /// NodeSelectPage.xaml 的交互逻辑
    /// </summary>
    public partial class NodeSelectPage : Page
    {
        private TreeNode RootNode = new TreeNode("Nodes");
        private SpeedUpServer _tempSelected = null;
        private SpeedUpServer TempSelected
        {
            get { return _tempSelected; }
            set
            {
                _tempSelected = value;
                if (value != null)
                {
                    PreviewName_Text.Text = value.Name;
                    PreviewPing_Text.Text = value.Ping > 0 ? value.Ping.ToString() : "999";
                }
            }
        }
        private SpeedUpServer BestNode = null;
        private SpeedUpServer _selectedServer = null;
        private SpeedUpServer SelectedServer
        {
            get { return _selectedServer; }
            set
            {
                _selectedServer = value;
                if (value != null)
                {
                    Name_Text.Text = value.Name;
                    Ping_Text.Text = value.Ping > 0 ? value.Ping.ToString() : "999";
                }
            }
        }
        public NodeSelectPage()
        {
            InitializeComponent();
            TempSelected = GlobalData.SelectedServerInfo;
            SelectedServer = GlobalData.SelectedServerInfo;
            BestNode = GlobalData.ServerInfos.Where(x => x.IsBest).FirstOrDefault();
            //var groups = GlobalData.ServerInfos.GroupBy(x => x.Province).ToList();
            RootNode.Children.Add(new TreeNode("The Fastest Node", BestNode));
            var servers = GlobalData.ServerInfos.OrderBy(x=>x.Name).ToList();
            foreach (var server in GlobalData.ServerInfos)
            {
                RootNode.Children.Add(new TreeNode(server.Name, server));
            }
            //foreach (var group in groups)
            //{
            //    //Console.WriteLine($"Province: {group.Key}");
            //    var provinceNode = new TreeNode(group.Key);
            //    RootNode.Children.Add(provinceNode);
            //    //if(group.Key == GlobalData.userInfo.Ipgeo.Province)
            //    //{
            //    //    TempSelected = group.First();
            //    //}
            //    foreach (var server in group)
            //    {

            //        provinceNode.Children.Add(new TreeNode(server.Name, server));
            //        //Console.WriteLine($"  Server Name: {server.Name}, City: {server.City}");
            //    }
            //}

            TreeView1.ItemsSource = new List<TreeNode> { RootNode };

        }
        private TreeViewItem FindTreeViewItemByName(ItemsControl container, string name)
        {
            if (container == null)
                return null;

            TreeNode node = container.DataContext as TreeNode;
            if (node != null && node.Name == name)
                return container as TreeViewItem;

            // Expand the container to make sure the item is generated
            if (container is TreeViewItem treeViewItem)
                treeViewItem.IsExpanded = true;

            container.ApplyTemplate();
            ItemsPresenter itemsPresenter = container.Template.FindName("ItemsHost", container) as ItemsPresenter;
            if (itemsPresenter != null)
                itemsPresenter.ApplyTemplate();

            ItemContainerGenerator itemContainerGenerator = container.ItemContainerGenerator;
            foreach (object childItem in container.Items)
            {
                TreeViewItem childContainer = itemContainerGenerator.ContainerFromItem(childItem) as TreeViewItem;
                TreeViewItem resultContainer = FindTreeViewItemByName(childContainer, name);
                if (resultContainer != null)
                    return resultContainer;
            }

            return null;
        }

        private void ExpandTreeViewItemByName(string name)
        {
            TreeViewItem item = FindTreeViewItemByName(TreeView1, name);
            if (item != null)
            {
                item.IsExpanded = true;
                item.BringIntoView();
            }
        }

        private void SelectTreeViewItemByName(string name)
        {
            TreeViewItem item = FindTreeViewItemByName(TreeView1, name);
            if (item != null)
            {
                item.IsExpanded = true;
                item.IsSelected = true;
                item.BringIntoView();
            }
        }
        private void TreeView1_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            // 处理双击事件
            var selectedItem = TreeView1.SelectedItem as TreeNode; // 替换为你的数据类型
            if (selectedItem != null)
            {
                if (selectedItem.Server == null)
                {
                    return;
                }
                GlobalData.SelectedServerInfo = selectedItem.Server;
                SelectedServer = selectedItem.Server;
                Name_Text.Text = selectedItem.Server.Name;
                Ping_Text.Text = selectedItem.Server.Ping.ToString();
            }
        }

        private void TreeView1_SelectedItemChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
        {
            // 处理单击事件
            var selectedItem = TreeView1.SelectedItem as TreeNode; // 替换为你的数据类型
            if (selectedItem != null)
            {
                if (selectedItem.Server == null)
                {
                    return;
                }
                TempSelected = selectedItem.Server;
                PreviewName_Text.Text = selectedItem.Server.Name;
                PreviewPing_Text.Text = selectedItem.Server.Ping.ToString();
            }
        }

        private void Page_Loaded(object sender, RoutedEventArgs e)
        {
            //GlobalData.userInfo.Ipgeo.Province;
            //expand the treeview
        }

        private void TreeView1_Loaded(object sender, RoutedEventArgs e)
        {
            if (SelectedServer != null)
            {
                SelectTreeViewItemByName(SelectedServer.Name);
            }
            else
            {
                SelectTreeViewItemByName("The Fastest Node");
            }
        }

    }
}
