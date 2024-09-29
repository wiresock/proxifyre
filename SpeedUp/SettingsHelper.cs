using SpeedUp.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SpeedUp
{
    internal class SettingsHelper
    {
        public Settings Settings { get; set; }
        // 私有静态变量来保存单例实例
        private static readonly SettingsHelper instance = new SettingsHelper();

        // 私有构造函数，防止外部实例化
        private SettingsHelper()
        {
            try
            {
                this.Settings = DataPersistence.LoadData<Settings>() ?? new Settings();
            }
            catch (Exception e)
            {
                this.Settings = new Settings();
            }
        }

        // 公共静态属性来获取单例实例
        public static SettingsHelper Instance
        {
            get
            {
                return instance;
            }
        }
        public void LoadSettings()
        {
            this.Settings = DataPersistence.LoadData<Settings>();
        }

        public void SaveSettings()
        {
            DataPersistence.SaveData(this.Settings);
        }
    }
}
