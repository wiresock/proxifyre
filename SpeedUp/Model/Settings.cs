using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SpeedUp.Model
{
    internal class Settings
    {
        public List<SpeedUpServer> ServerList { get; set; } = new List<SpeedUpServer>();
        public List<string> FilePaths { get; set; } = new List<string>();
        public bool CreateShortCut { get; set; } = true;
    }
}
