using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NSP2.Client
{
    /// <summary>
    /// Provides Client-level access to a connected user, without providing any confidential information.
    /// </summary>
    public class NSP2ConnectedUser
    {
        public string? IP { set; get; } = null;
        public string ID { set; get; } = "";

        public string? AccountName { set; get; } = "";

        public DateTime ConnectTime { set; get; } = DateTime.Now;

        public bool IsServer { set; get; } = false;

        public TimeSpan ConnectDuration
        {
            get
            {
                return DateTime.Now - ConnectTime;
            }
        }
    }
}
