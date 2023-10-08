using NSP2.Client;
using NSP2.JSON;
using NSP2.Util;
using NSP2Lib.JSON;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static NSP2.Server.NSP2ServerClient.ServerPunishmentEventArgs;

namespace NSP2.Server
{
    public class NSP2ServerClient
    {
        public string IP { set; get; }

        public string ID { set; get; }

        public DateTime ConnectTime { set; get; }

        public NSP2PermissionList Permissions { set; get; }

        public string? AccountName { set; get; } = null;

        public TcpClient Socket { private set; get; }

        public bool IsKicked { private set; get; } = false;

        public bool IsBanned { private set; get; } = false;

        public bool IsMuted { private set; get; } = false;

        public string PunishmentReason { private set; get; } = "";

        public event EventHandler<ServerPunishmentEventArgs>? OnPunish;

        public event EventHandler<ServerClientEventArgs>? OnMuteRemoved;

        public bool IsConnected
        {
            get
            {
                return Socket.Connected;
            }
        }

        public NSP2ConnectedUser ToUser(bool protectIP=false)
        {
            return new NSP2ConnectedUser()
            {
                ID = this.ID,
                IP = (protectIP) ? null : this.IP,
                IsServer = false,
                ConnectTime = this.ConnectTime,
                AccountName = this.AccountName
            };
        }

        public bool Equals(NSP2ServerClient? obj)
        {
            if (obj == null)
                return false;
            return obj.ID.Equals(ID);
        }

        public NSP2ServerClient(TcpClient socket, string id, NSP2PermissionList permissions)
        {
            Socket = socket;
            Permissions = permissions;
            IP = string.Empty;
            ID = id;

            if (socket.Client.RemoteEndPoint == null)
                return;
            try
            {
                IP = ((IPEndPoint)socket.Client.RemoteEndPoint).Address.ToString();
            } catch (Exception)
            { }
        }

        public class ServerPunishmentEventArgs : EventArgs
        {
            
            public PunishmentType Type { get; }
            public DateTime Time { get; }
            public NSP2ServerClient Client { get; }

            public string Reason { get; }

            public ServerPunishmentEventArgs(NSP2ServerClient client, PunishmentType type, DateTime time, string reason)
            {
                Time = time;
                Type = type;
                Client = client;
                Reason = reason;
            }
        }

        public class ServerClientEventArgs : EventArgs
        {
            public DateTime Time { get; }
            public NSP2ServerClient Client { get; }

            public ServerClientEventArgs(NSP2ServerClient client,  DateTime time)
            {
                Time = time;
                Client = client;
            }
        }

        public class ServerSendMessageEventArgs : EventArgs
        {
            public NSP2ServerClient Client { get; }
            public byte[] Bytes { get; }

            public ServerSendMessageEventArgs(NSP2ServerClient client, byte[] bytes)
            {
                Client = client;
                Bytes = bytes;
            }
        }

        public void Mute(string reason="")
        {
            if (!IsMuted)
            {
                PunishmentReason = reason;
                IsMuted = true;
                OnPunish?.Invoke(this, new ServerPunishmentEventArgs(this, PunishmentType.MUTE, DateTime.Now, reason));
            }
        }

        public void Ban(string reason="")
        {
            if (!IsBanned)
            {
                PunishmentReason = reason;
                IsBanned = true;
                OnPunish?.Invoke(this, new ServerPunishmentEventArgs(this, PunishmentType.BAN, DateTime.Now, reason));
            }
        }

        public void Kick(string reason = "")
        {
            if (!IsKicked)
            {
                PunishmentReason = reason;
                IsKicked = true;
                OnPunish?.Invoke(this, new ServerPunishmentEventArgs(this, PunishmentType.KICK, DateTime.Now, reason));
            }
        }

        public void Unmute()
        {
            if (IsMuted)
            {
                PunishmentReason = "";
                IsMuted = false;
                OnMuteRemoved?.Invoke(this, new ServerClientEventArgs(this, DateTime.Now));
            }
        }
    }
}
