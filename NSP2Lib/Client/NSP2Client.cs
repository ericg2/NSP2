

using Newtonsoft.Json;
using NSP2.Client;
using NSP2.JSON;
using NSP2.JSON.Message;
using NSP2.Util;
using NSP2Lib.JSON;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Transactions;
using static NSP2.Client.NSP2ConnectedUser;
using static NSP2.JSON.NSP2Request;
using static NSP2.JSON.NSP2Response;
/**
* Copyright(c) 2023 Eric Gold (ericg2)
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
namespace NSP2Lib.Client
{
    public class NSP2Client
    {
        public TcpClient? Client { set; get; } = null;

        public int Port { private set; get; } = 8080;

        public string IP { private set; get; } = "";

        public bool UsingCompression { private set; get; } = false;

        public bool ServerPasswordRequired { private set; get; } = false;

        public string? ServerPassword { set; get; } = "";

        public string? AccountName { set; get; } = null;

        public string? AccountPassword { set; get; } = null;

        public event EventHandler<ClientUserEventArgs>? OnClientConnected;

        public event EventHandler<ClientUserEventArgs>? OnClientDisconnected;

        public event EventHandler<MessageReceivedEventArgs>? OnMessageReceived;

        public event EventHandler<PunishmentEventArgs>? OnPunished;

        public event EventHandler<SocketEventArgs>? OnMuteRemoved;

        public event EventHandler<SocketEventArgs>? OnSocketConnected;

        public event EventHandler<SocketEventArgs>? OnSocketDisconnected;

        private StatusResponseTemplate? _ServerStatus = null;

        private Thread? _ReceiveThread = null;

        public bool IsConnected
        {
            get
            {
                if (Client == null)
                    return false;
                return Client.Connected;
            }
        }

        public bool IsMuted { private set; get; } = false;

        public bool IsBanned { private set; get; } = false;

        public bool IsKicked { private set; get; } = false;

        public StatusResponseTemplate? ServerStatus
        {
            get
            {
                return _ServerStatus;
            }
        }

        private byte[]? ServerPasswordKey
        {
            get
            {
                if (string.IsNullOrEmpty(ServerPassword))
                    return null;
                try
                {
                    return SHA256.Create().ComputeHash(NSP2Util.ENCODING.GetBytes(ServerPassword));
                } catch (Exception)
                {
                    return null;
                }
            }
        }

        private byte[]? AccountPasswordKey
        {
            get
            {
                if (string.IsNullOrEmpty(AccountPassword))
                    return null;
                try
                {
                    return SHA256.Create().ComputeHash(NSP2Util.ENCODING.GetBytes(AccountPassword));
                } catch (Exception)
                {
                    return null;
                }
            }
        }

        private void SendIfNotNull(TcpClient sock, byte[]? bytes)
        {
            try
            {
                if (bytes == null)
                    return;
                sock.GetStream().Write(bytes);
            } catch (Exception)
            { }
        }

        private void SendIfNotNull(TcpClient sock, NSP2Request req, bool useClientSettings = true)
        {
            byte[]? passwordKey = useClientSettings ? ServerPasswordKey : null;
            bool compression = useClientSettings ? UsingCompression : false;

            SendIfNotNull(sock, NSP2Util.GeneratePacket(req, passwordKey, compression));
        }

        public bool Send(NSP2Request req)
        {
            if (Client == null)
                return false;
            SendIfNotNull(Client, req);
            return true;
        }

        public bool Send(byte[] reqBytes)
        {
            if (Client == null)
                return false;
            SendIfNotNull(Client, reqBytes);
            return true;
        }

        private void ReceiveMessageThread()
        {
            if (Client == null)
                return;

            DateTime nextKeepAlive = DateTime.Now;
            DateTime nextStatus = DateTime.Now.AddSeconds(10);

            while (IsConnected && !IsKicked && !IsBanned)
            {
                try
                {
                    if (DateTime.Now >= nextKeepAlive)
                    {
                        SendIfNotNull(Client, new NSP2Request()
                        {
                            Message = "",
                            Type = RequestAction.KEEP_ALIVE
                        });
                        nextKeepAlive = DateTime.Now + (_ServerStatus == null ? TimeSpan.FromSeconds(30) : _ServerStatus.KeepAliveInterval);
                    }

                    if (DateTime.Now >= nextStatus)
                    {
                        SendIfNotNull(Client, new NSP2Request()
                        {
                            Message = "",
                            Type = RequestAction.GET_STATUS
                        });
                        nextStatus = DateTime.Now + TimeSpan.FromSeconds(30);
                    }

                    NSP2Response? res = NSP2Util.ReceivePacket<NSP2Response>(Client, out _, ServerPasswordKey, UsingCompression, TimeSpan.FromSeconds(5));

                    if (res == null)
                        continue;


                    if (res.Result == StatusMessage.DISCONNECTED)
                        break;

                    switch (res.Result)
                    {
                        case StatusMessage.MUTED:
                            {
                                IsMuted = true;
                                OnPunished?.Invoke(this, new PunishmentEventArgs(this, DateTime.Now, PunishmentType.MUTE));
                                break;
                            }
                        case StatusMessage.KICKED:
                            {
                                IsKicked = true;
                                OnPunished?.Invoke(this, new PunishmentEventArgs(this, DateTime.Now, PunishmentType.KICK));
                                break;
                            }
                        case StatusMessage.BANNED:
                            {
                                IsBanned = true;
                                OnPunished?.Invoke(this, new PunishmentEventArgs(this, DateTime.Now, PunishmentType.BAN));
                                break;
                            }
                        case StatusMessage.UNMUTED:
                            {
                                IsMuted = false;
                                OnMuteRemoved?.Invoke(this, new SocketEventArgs(this, DateTime.Now));
                                break;
                            }
                        case StatusMessage.DISCONNECTED_EVENT:
                        case StatusMessage.CONNECTED_EVENT:
                            {
                                // Attempt to gather more specifics.
                                NSP2ConnectedUser? user = null;

                                if (!string.IsNullOrEmpty(res.Message))
                                {
                                    user = JsonConvert.DeserializeObject<NSP2ConnectedUser>(res.Message);
                                }

                                if (user == null || NSP2Util.IsDefault<NSP2ConnectedUser>(user))
                                    user = null; // prevent default values from displaying.

                                if (res.Result == StatusMessage.CONNECTED_EVENT)
                                    OnClientConnected?.Invoke(this, new ClientUserEventArgs(user, DateTime.Now));
                                else if (res.Result == StatusMessage.DISCONNECTED_EVENT)
                                    OnClientDisconnected?.Invoke(this, new ClientUserEventArgs(user, DateTime.Now));
                                break;
                            }
                        case StatusMessage.STATUS_EVENT:
                            {
                                _ServerStatus = JsonConvert.DeserializeObject<StatusResponseTemplate>(res.Message);
                                if (_ServerStatus == null)
                                    break;
                                UsingCompression = _ServerStatus.IsCompressionRequired;
                                break;
                            }
                        case StatusMessage.MESSAGE_RECEIVE:
                            {
                                OnMessageReceived?.Invoke(this, new MessageReceivedEventArgs(res, DateTime.Now));
                                break;
                            }
                        default:
                            break;
                    }
                }
                catch (Exception ex)
                {
                    if (ex.InnerException is SocketException)
                    {
                        return;
                    }
                    continue;
                }
            }
        }

        public bool Stop()
        {
            if (Client == null)
                return false;
            Client.Close();
            Client = null;
            _ReceiveThread = null;
            return true;
        }

        public bool Start(TimeSpan? timeout=null)
        {
            //if (timeout == null)
            //    timeout = TimeSpan.FromSeconds(5);


            if (Client != null || _ReceiveThread != null)
                return false;

            if (!IPAddress.TryParse(IP, out _))
                return false;
            if (Port >= 65535 || Port <= 1023)
                return false;
            Client = new TcpClient(IP, Port);

            // Wait for a Server Status message.
            NSP2Response? res = NSP2Util.ReceivePacket<NSP2Response>(Client, out _, ServerPasswordKey, UsingCompression, timeout);
            if (res == null)
            {
                Stop();
                return false;
            }

            _ServerStatus = JsonConvert.DeserializeObject<StatusResponseTemplate>(res.Message);
            if (_ServerStatus == null)
            {
                Stop();
                return false;
            }
            UsingCompression = _ServerStatus.IsCompressionRequired;

            // See if a password is required, and none is specified.
            if (_ServerStatus.IsPasswordRequired && string.IsNullOrEmpty(ServerPassword))
            {
                Stop();
                return false;
            }

            // Generate an authenticate packet and attempt.
            NSP2Request? req = ParseAuth(AccountName, AccountPasswordKey);
            if (req == null)
            {
                Stop();
                return false;
            }

            SendIfNotNull(Client, req);

            DateTime expire = DateTime.Now + TimeSpan.FromSeconds(10);
            while (DateTime.Now <= expire)
            {
                NSP2Response? handshake = NSP2Util.ReceivePacket<NSP2Response>(Client, out _, ServerPasswordKey, UsingCompression, TimeSpan.FromSeconds(5));
                if (handshake == null)
                {
                    // Password was most likely incorrect, or internal error occurred.
                    Stop();
                    return false;
                }

                if (handshake.Result == StatusMessage.CONNECTED)
                {
                    _ReceiveThread = new Thread(ReceiveMessageThread);
                    _ReceiveThread.Start();
                    return true;
                } 
            }
            Stop();
            return false;
        }

        public NSP2Client(string ipAddress, int port)
        {
            IP = ipAddress;
            Port = port;

            // Attempt to receive the Server Status before connection
            /*
            try
            {
                using (TcpClient cli = new TcpClient(ipAddress, port))
                {
                    NSP2Response? res = NSP2Util.ReceivePacket<NSP2Response>(cli, out _, ServerPasswordKey, UsingCompression, TimeSpan.FromSeconds(5));
                    if (res == null)
                        return;

                    _ServerStatus = JsonConvert.DeserializeObject<StatusResponseTemplate>(res.Message);
                    if (_ServerStatus == null)
                        return;
                    UsingCompression = _ServerStatus.IsCompressionRequired;
                    return;
                }
            } catch (Exception)
            { }
            */
        }

        public class MessageReceivedEventArgs : EventArgs
        {
            public NSP2Response Response { get; }
            public DateTime Time { get; }

            public MessageReceivedEventArgs(NSP2Response res, DateTime time)
            {
                Response = res;
                Time = time;
            }
        }

        public class SocketEventArgs : EventArgs
        {
            public NSP2Client Client { get; }
            public DateTime Time { get; }

            public SocketEventArgs(NSP2Client client, DateTime time)
            {
                Client = client;
                Time = time;
            }
        }

        public class PunishmentEventArgs : SocketEventArgs
        {
            public PunishmentType Type { get; }

            public PunishmentEventArgs(NSP2Client client, DateTime time, PunishmentType type) : base(client, time)
            {
                Type = type;
            }
        }
    }
}
