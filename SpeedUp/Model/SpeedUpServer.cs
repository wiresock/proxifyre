using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SpeedUp.Model
{
    public class SpeedUpServer
    {
        public long Id { get; set; }
        public bool Enabled { get; set; }
        public string Name { get; set; }
        public string Host { get; set; }
        public short Port { get; set; }
        public string Username { get; set; }
        public string Secret { get; set; }

        // Client side only
        public double Ping { get; set; } = -1;
        public bool IsSelected { get; set; } = false;
        public bool IsBest { get; set; } = false;
    }
}
