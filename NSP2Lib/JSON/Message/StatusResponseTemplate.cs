using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NSP2.Client;
using NSP2.JSON;
using NSP2.Server;

namespace NSP2.JSON.Message
{
    public class StatusResponseTemplate
    {
        public string IP { set; get; } = "";
        public int Port { set; get; } = 0;

        public int MaxClients { set; get; } = -1;

        public int MaxConcurrent { set; get; } = -1;

        public List<NSP2ConnectedUser>? Clients { set; get; } = null;

        public bool IsPasswordRequired { set; get; } = false;

        public bool IsAddressProtected { set; get; } = false;

        public bool IsCompressionRequired { set; get; } = false;

        public List<NSP2Permission> DefaultPermissions { set; get; } = new List<NSP2Permission>();

        public TimeSpan Uptime { set; get; } = TimeSpan.Zero;
    }
}
