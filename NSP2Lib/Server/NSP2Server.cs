/**
 * Copyright (c) 2023 Eric Gold (ericg2)
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

using Newtonsoft.Json;
using NSP2.Client;
using NSP2.JSON;
using NSP2.JSON.Message;
using NSP2.Util;
using NSP2Lib.JSON;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using static NSP2.JSON.Message.UserReferenceTemplate;
using static NSP2.JSON.NSP2Request;
using static NSP2.JSON.NSP2Response;
using static NSP2.Server.NSP2ServerClient;
using static NSP2.Server.NSP2ServerClient.ServerPunishmentEventArgs;

namespace NSP2.Server
{
    public class NSP2Server
    {
        public class MutableKeyValuePair<K, V>
        {
            public K Key { get; set; }
            public V Value { get; set; }

            public MutableKeyValuePair(K key, V val)
            {
                this.Key = key;
                this.Value = val;
            }
        }

        [JsonIgnore]
        public static readonly int UNLIMITED = -1;

        public int Port { set; get; } = 8080;

        public TimeSpan KeepAliveInterval { set; get; } = TimeSpan.FromSeconds(30);

        public int MaxClients { set; get; } = UNLIMITED;

        public int MaxConcurrent { set; get; } = UNLIMITED;

        public string? Password { set; get; } = null;

        public bool UseAddressProtection { set; get; } = false;

        public bool UseCompression { set; get; } = false;

        public string IP
        {
            get
            {
                if (IPObject == null)
                    return "";
                else
                    return IPObject.ToString();
            }
        }

        private IPAddress? IPObject
        {
            get
            {
                foreach (IPAddress ip in Dns.GetHostEntry(Dns.GetHostName()).AddressList)
                {
                    if (ip.AddressFamily == AddressFamily.InterNetwork)
                        return ip;
                }
                return null;
            }
        }

        [JsonIgnore]
        public bool IsRunning { set; get; } = false;

        public NSP2PermissionList DefaultPermissions { set; get; } = new NSP2PermissionList()
        {
            NSP2Permission.READ,
            NSP2Permission.WRITE
        };

        public List<NSP2Account> Accounts { set; get; } = new List<NSP2Account>();

        public DateTime StartTime { private set; get; } = DateTime.Now;

        public TimeSpan Uptime
        {
            get
            {
                if (StartTime == DateTime.MinValue)
                    return TimeSpan.FromSeconds(0);
                return DateTime.Now - StartTime;
            }
        }

        [JsonIgnore]
        public List<NSP2ServerClient> Clients
        {
            get
            {
                List<NSP2ServerClient> output = new List<NSP2ServerClient>();
                lock (_ClientManagerLock)
                {
                    foreach (KeyValuePair<NSP2ServerClient, MutableKeyValuePair<Thread, ClientState>> kvp in _ClientManagers)
                    {
                        if (kvp.Value.Value == ClientState.CONNECTED)
                            output.Add(kvp.Key);
                    }
                }
                return output;
            }
        }

        public event EventHandler<ClientMessageReceivedEventArgs>? OnMessageReceived;

        public event EventHandler<ServerClientEventArgs>? OnClientConnected;

        public event EventHandler<ClientDisconnectEventArgs>? OnClientDisconnected;

        public event EventHandler<ServerPunishmentEventArgs>? OnPunished;

        public event EventHandler<ServerClientEventArgs>? OnMuteRemoved;

        public event EventHandler<ServerModifyEventArgs>? OnServerStarted;

        public event EventHandler<ServerModifyEventArgs>? OnServerStopped;

        ////////////////////////////////////////////////////////////////
        
        private enum ClientState
        {
            HANDSHAKE, CONNECTED
        }

        private Dictionary<NSP2ServerClient, 
            MutableKeyValuePair<Thread, ClientState>> _ClientManagers = new Dictionary<NSP2ServerClient, MutableKeyValuePair<Thread, ClientState>>();

        private Thread? _AcceptThread = null;
        private TcpListener? _Socket = null;

        private object _ClientManagerLock = new object();
        private object _AccountListLock = new object();

        private byte[]? PasswordKey
        {
            get
            {
                if (string.IsNullOrEmpty(Password))
                    return null;
                try
                {
                    return SHA256.Create().ComputeHash(NSP2Util.ENCODING.GetBytes(Password));
                }
                catch (Exception)
                {
                    return null;
                }
            }
        }
    
        public bool SaveSettings(string filePath)
        {
            if (Directory.Exists(filePath))
                return false;
            try
            {
                File.WriteAllText(filePath, JsonConvert.SerializeObject(this));
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        // VULNERABILITY: a huge amount of clients can exhaust the IP list.
        private string GetNextID()
        {
            while (true)
            {
                string id = "ID-" + NSP2Util.GenerateRandomString(8);
                lock (_ClientManagerLock)
                {
                    foreach (NSP2ServerClient cli in Clients)
                    {
                        if (cli.ID.Equals(id))
                            continue;
                    }
                }
                return id;
            }
        }

        public NSP2Server(int port=8080)
        {
            Port = port;
        }

        public NSP2Server(string filePath, int port=8080)
        {
            NSP2Server? server = JsonConvert.DeserializeObject<NSP2Server>(File.ReadAllText(filePath));
            if (server == null)
                return;
            Port = port;
            MaxClients = server.MaxClients;
            MaxConcurrent = server.MaxConcurrent;
            Password = server.Password;
            UseAddressProtection = server.UseAddressProtection;
            UseCompression = server.UseCompression;
            DefaultPermissions = server.DefaultPermissions;
            Accounts = server.Accounts;
        }

        private StatusResponseTemplate GenerateStatusResponse(bool viewClients, NSP2ServerClient? client=null)
        {
            List<NSP2ConnectedUser> users = new List<NSP2ConnectedUser>();

            if (viewClients)
            {
                lock (_ClientManagerLock)
                {
                    foreach (NSP2ServerClient cli in Clients)
                    {
                        users.Add(cli.ToUser());
                    }
                }
            }

            return new StatusResponseTemplate()
            {
                IP = this.IP,
                Port = this.Port,
                MaxClients = this.MaxClients,
                MaxConcurrent = this.MaxConcurrent,
                IsPasswordRequired = !string.IsNullOrEmpty(Password),
                IsAddressProtected = UseAddressProtection,
                IsCompressionRequired = UseCompression,
                DefaultPermissions = (client != null) ? client.Permissions : this.DefaultPermissions,
                CurrentPermissions = this.DefaultPermissions,
                Uptime = this.Uptime,
                ConnectedClients = Clients.Count,
                Clients = viewClients ? users : null,
                KeepAliveInterval = this.KeepAliveInterval
            };
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

        private void SendIfNotNull(TcpClient sock, StatusMessage message, string details="", bool useServerSettings=true)
        {
            byte[]? passwordKey = useServerSettings ? PasswordKey : null;
            bool compression = useServerSettings ? UseCompression : false;

            SendIfNotNull(sock, NSP2Util.GeneratePacket(new NSP2Response()
            {
                SentBy = null,
                Result = message,
                Message = details
            }, passwordKey, compression, false));
        }

        private int[] GetClientIndex(string reference, UpdateType type)
        {
            List<int> indexes = new List<int>();

            for (int i=0; i<Clients.Count; i++)
            {
                if (type == UpdateType.ID_IP)
                {
                    if (NSP2Util.IsID(reference))
                    {
                        if (Clients[i].ID.Equals(reference))
                            return new int[] { i };
                    }
                    else
                    {
                        if (Clients[i].IP.Equals(reference))
                            return new int[] { i };
                    }
                }
                else if (type == UpdateType.ACCOUNT_NAME)
                {
                    string? acc = Clients[i].AccountName;
                    if (acc == null)
                        continue;
                    if (acc.Equals(reference))
                        indexes.Add(i);
                }
                else
                {
                    break;
                }
            }
            return indexes.ToArray();
        }

        private void HandleClientThread()
        {
            NSP2ServerClient? client = null;
            ClientState? state = null;
            DateTime handshakeExpire = DateTime.Now.AddSeconds(3000000); //30
            DateTime handshakeNextStatus = DateTime.Now;
            bool noResponse = true;

            while (true)
            {
                client = null;

                lock (_ClientManagerLock)
                {
                    foreach (KeyValuePair<NSP2ServerClient, MutableKeyValuePair<Thread, ClientState>> kvp in _ClientManagers)
                    {
                        if (kvp.Value.Key.ManagedThreadId == Thread.CurrentThread.ManagedThreadId) 
                        {
                            client = kvp.Key;
                            state = kvp.Value.Value;
                            break;
                        }
                    }
                }

                if (state == null)
                    break;

                if (client == null || !client.IsConnected)
                    break;

                if (client.IsBanned || client.IsKicked)
                    break;

                if (state == ClientState.HANDSHAKE)
                {
                    if (noResponse && DateTime.Now >= handshakeNextStatus)
                    {
                        // Use no encryption since the client did not acknowledge.
                        StatusResponseTemplate status = GenerateStatusResponse(DefaultPermissions.IsAdminOr(NSP2Permission.VIEW_CLIENTS));
                        SendIfNotNull(client.Socket, StatusMessage.STATUS_EVENT, JsonConvert.SerializeObject(status), false);
                        handshakeNextStatus = DateTime.Now.AddSeconds(10);
                    }
                }

                bool loopBack;
                byte[]? packetBytes = NSP2Util.ReceivePacketBytes(client.Socket, out loopBack, PasswordKey, UseCompression, TimeSpan.FromSeconds(5));

                if (packetBytes == null)
                    continue;

                if (loopBack && state == ClientState.CONNECTED)
                {
                    // The message was the result of a relay from another client.
                    NSP2Response? res = JsonConvert.DeserializeObject<NSP2Response>(NSP2Util.ENCODING.GetString(packetBytes));
                    if (res == null)
                        continue;
                    if (res.SentBy != null && res.SentBy.Equals(client.ID))
                        continue; // The client has sent this message already.
                    if (client.Permissions.IsAdminOr(NSP2Permission.READ))
                        OnMessageReceived?.Invoke(this, new ClientMessageReceivedEventArgs(client, res, DateTime.Now));
                    continue;
                }

                NSP2Request? req = JsonConvert.DeserializeObject<NSP2Request>(NSP2Util.ENCODING.GetString(packetBytes));
                if (req == null)
                    continue;

                if (state == ClientState.HANDSHAKE)
                {
                    if (req.Type != RequestAction.AUTHENTICATE)
                    {
                        // No other operations are supported at this moment, except Authenticate.
                        SendIfNotNull(client.Socket, StatusMessage.OPERATION_FAILURE, "Only AUTHENTICATE is supported at this stage.");
                        continue;
                    }

                    if (MaxClients >= 0)
                    {
                        lock (_ClientManagerLock)
                        {
                            if (_ClientManagers.Count >= MaxClients)
                            {
                                SendIfNotNull(client.Socket, StatusMessage.OPERATION_FAILURE, "Maximum connections reached.");
                                continue;
                            }
                        }
                    }

                    int ipCount = 0;

                    EndPoint? ep = client.Socket.Client.RemoteEndPoint;
                    if (ep == null)
                        break;

                    string ip = ((IPEndPoint)ep).Address.ToString();
                    if (MaxConcurrent >= 0)
                    {
                        lock (_ClientManagerLock)
                        {
                            foreach (NSP2ServerClient cli in Clients)
                            {
                                if (cli.IP.Equals(ip))
                                {
                                    ipCount++;
                                }
                            }

                            if (ipCount >= MaxConcurrent)
                            {
                                SendIfNotNull(client.Socket, StatusMessage.OPERATION_FAILURE, "Maximum concurrent connections reached.");
                                continue;
                            }
                        }
                    }

                    noResponse = false;

                    AuthTemplate? auth = JsonConvert.DeserializeObject<AuthTemplate>(req.Message);
                    /********************************* ACKNOWLEDGEMENT SUCCESSFUL ************************/

                    // Attempt to decode the message template. This is NOT required, but allows for additional permissions.
                    if (auth != null && !string.IsNullOrEmpty(auth.AccountName) && !string.IsNullOrEmpty(auth.Token))
                    {
                        try
                        {
                            NSP2Account? reqAccount = null;
                            lock (_AccountListLock)
                            {
                                foreach (NSP2Account acc in Accounts)
                                {
                                    if (auth.AccountName.Equals(acc.AccountName))
                                    {
                                        reqAccount = acc;
                                        break;
                                    }
                                }
                            }

                            if (reqAccount == null || reqAccount.HashedPassword == null)
                                throw new Exception();

                            // Attempt to decode the token.
                            byte[]? decryptBytes = NSP2Util.Decrypt(Convert.FromBase64String(auth.Token), reqAccount.HashedPassword);

                            if (decryptBytes == null || decryptBytes.Length == 0 || !NSP2Util.ENCODING.GetString(decryptBytes).Equals("AUTH"))
                                throw new Exception();

                            // The account has been successfully authenticated.
                            client.AccountName = reqAccount.AccountName;
                            client.Permissions = reqAccount.Permissions;
                        } catch (Exception)
                        {
                            SendIfNotNull(client.Socket, StatusMessage.OPERATION_FAILURE, "Authentication Failed.", true);
                        }
                    }

                    byte[]? relayByte = NSP2Util.GeneratePacket(new NSP2Response()
                    {
                        Message = JsonConvert.SerializeObject(client.ToUser(UseAddressProtection)),
                        Result = StatusMessage.CONNECTED_EVENT
                    }, PasswordKey, UseCompression, true);

                    lock (_ClientManagerLock)
                    {
                        _ClientManagers[client].Value = ClientState.CONNECTED;
                        OnClientConnected?.Invoke(this, new ServerClientEventArgs(client, DateTime.Now));

                        foreach (NSP2ServerClient cli in Clients)
                        {
                            if (cli.Equals(client))
                                continue; // do not duplicate.
                            SendIfNotNull(cli.Socket, relayByte);
                        }
                    }
                    continue;
                }

                try
                {
                    switch (req.Type)
                    {
                        case RequestAction.SEND_MESSAGE:
                            {
                                // Check if the user has permission to send messages.
                                if (!client.Permissions.IsAdminOr(NSP2Permission.WRITE))
                                    break;

                                // Create a NSP2Response to relay.
                                byte[]? relayBytes = NSP2Util.GeneratePacket(new NSP2Response()
                                {
                                    Result = StatusMessage.MESSAGE_RECEIVE,
                                    Message = req.Message,
                                    SentBy = client.ToUser()
                                }, PasswordKey, UseCompression, true);

                                if (relayBytes == null)
                                    break;

                                lock (_ClientManagerLock)
                                {
                                    foreach (NSP2ServerClient cli in Clients)
                                    {
                                        if (!cli.Permissions.IsAdminOr(NSP2Permission.READ))
                                            continue;
                                        cli.Socket.GetStream().Write(relayBytes);
                                    }
                                }

                                break;
                            }
                        case RequestAction.GET_STATUS:
                            {
                                // Send a response.
                                StatusResponseTemplate status = GenerateStatusResponse(client.Permissions.IsAdminOr(NSP2Permission.VIEW_CLIENTS), client);
                                SendIfNotNull(client.Socket, StatusMessage.STATUS_EVENT, JsonConvert.SerializeObject(status), true);
                                break;
                            }
                        case RequestAction.UPDATE_PERMISSION:
                            {
                                // Only admins can use this feature.
                                if (!client.Permissions.IsAdmin())
                                {
                                    SendIfNotNull(client.Socket, StatusMessage.OPERATION_FAILURE);
                                }

                                // Check if message can decode to UpdatePermissionTemplate.
                                UpdatePermissionTemplate? perm = JsonConvert.DeserializeObject<UpdatePermissionTemplate>(req.Message);

                                if (perm == null || NSP2Util.IsDefault<UpdatePermissionTemplate>(perm))
                                {
                                    // Decoding failed. Return failure.
                                    SendIfNotNull(client.Socket, StatusMessage.OPERATION_FAILURE);
                                    break;
                                }

                                // Attempt to update permissions.
                                bool success = false;
                                lock (_ClientManagerLock)
                                {
                                    int[] cliIdx = GetClientIndex(perm.Reference, perm.Type);
                                    foreach (int idx in cliIdx)
                                    {
                                        Clients[idx].Permissions.Modify(perm.Permissions, perm.Mode);
                                        success = true;
                                    }
                                    if (perm.Type == UpdateType.ACCOUNT_NAME)
                                    {
                                        lock (_AccountListLock)
                                        {
                                            for (int i = 0; i < Accounts.Count; i++)
                                            {
                                                if (Accounts[i].AccountName.Equals(perm.Reference))
                                                    Accounts[i].Permissions.Modify(perm.Permissions, perm.Mode);
                                            }
                                        }
                                    }
                                }

                                SendIfNotNull(client.Socket, success ? StatusMessage.OPERATION_SUCCESS : StatusMessage.OPERATION_FAILURE);
                                break;
                            }
                        case RequestAction.KICK:
                        case RequestAction.BAN:
                        case RequestAction.MUTE:
                            {
                                // Check if user has the correct permission.
                                if (
                                    (req.Type == RequestAction.KICK && !client.Permissions.IsAdminOr(NSP2Permission.KICK)) ||
                                    (req.Type == RequestAction.BAN && !client.Permissions.IsAdminOr(NSP2Permission.BAN)) ||
                                    (req.Type == RequestAction.MUTE && !client.Permissions.IsAdminOr(NSP2Permission.MUTE)))
                                {
                                    SendIfNotNull(client.Socket, StatusMessage.OPERATION_FAILURE);
                                    break;
                                }

                                PunishTemplate? user = JsonConvert.DeserializeObject<PunishTemplate>(req.Message);

                                if (user == null || NSP2Util.IsDefault<PunishTemplate>(user))
                                {
                                    SendIfNotNull(client.Socket, StatusMessage.OPERATION_FAILURE);
                                    break;
                                }

                                bool success = false;
                                lock (_ClientManagerLock)
                                {
                                    int[] cliIdx = GetClientIndex(user.Reference, user.Type);
                                    foreach (int idx in cliIdx)
                                    {
                                        switch (req.Type)
                                        {
                                            case RequestAction.KICK:
                                                {
                                                    Clients[idx].Kick(user.Reason);
                                                    break;
                                                }
                                            case RequestAction.BAN:
                                                {
                                                    Clients[idx].Ban(user.Reason);
                                                    break;
                                                }
                                            case RequestAction.MUTE:
                                                {
                                                    Clients[idx].Mute(user.Reason);
                                                    break;
                                                }
                                        }
                                        success = true;
                                    }
                                    if (req.Type == RequestAction.BAN && user.Type == UpdateType.ACCOUNT_NAME)
                                    {
                                        // Ban the account name as well.
                                        lock (_AccountListLock)
                                        {
                                            int accIdx = Accounts.FindIndex(o => o.AccountName == user.Reference);
                                            if (accIdx >= 0)
                                            {
                                                Accounts[accIdx].IsBanned = true;
                                            }
                                        }
                                    }
                                }

                                SendIfNotNull(client.Socket, success ? StatusMessage.OPERATION_SUCCESS : StatusMessage.OPERATION_FAILURE);
                                break;
                            }
                        case RequestAction.UNBAN:
                        case RequestAction.UNMUTE:
                            {
                                // Check if user has the correct permission.
                                if (
                                    (req.Type == RequestAction.UNBAN && !client.Permissions.IsAdminOr(NSP2Permission.KICK)) ||
                                    (req.Type == RequestAction.UNMUTE && !client.Permissions.IsAdminOr(NSP2Permission.MUTE)))
                                {
                                    SendIfNotNull(client.Socket, StatusMessage.OPERATION_FAILURE);
                                    break;
                                }

                                UserReferenceTemplate? user = JsonConvert.DeserializeObject<UserReferenceTemplate>(req.Message);

                                if (user == null || NSP2Util.IsDefault<UserReferenceTemplate>(user))
                                {
                                    SendIfNotNull(client.Socket, StatusMessage.OPERATION_FAILURE);
                                    break;
                                }

                                bool success = false;
                                lock (_ClientManagerLock)
                                {
                                    int[] cliIdx = GetClientIndex(user.Reference, user.Type);
                                    foreach (int idx in cliIdx)
                                    {
                                        switch (req.Type)
                                        {
                                            case RequestAction.UNMUTE:
                                                {
                                                    Clients[idx].Unmute();
                                                    SendIfNotNull(Clients[idx].Socket, StatusMessage.UNMUTED);
                                                    break;
                                                }
                                            case RequestAction.UNBAN:
                                                {
                                                    // TODO: Implement!
                                                    break;
                                                }
                                        }
                                        success = true;
                                    }
                                    if (req.Type == RequestAction.UNBAN && user.Type == UpdateType.ACCOUNT_NAME)
                                    {
                                        // UnBan the account name as well.
                                        lock (_AccountListLock)
                                        {
                                            int accIdx = Accounts.FindIndex(o => o.AccountName == user.Reference);
                                            if (accIdx >= 0)
                                            {
                                                Accounts[accIdx].IsBanned = false;
                                            }
                                        }
                                    }

                                    SendIfNotNull(client.Socket, success ? StatusMessage.OPERATION_SUCCESS : StatusMessage.OPERATION_FAILURE);
                                    break;
                                }
                            }
                        default:
                            continue;
                    }
                } catch (Exception ex)
                {
                    if (ex.InnerException is SocketException)
                        break;
                    continue;
                }
            }

            if (client != null)
            {
                if (state == ClientState.CONNECTED)
                {
                    if (client.IsConnected)
                    {
                        if (client.IsBanned)
                        {
                            SendIfNotNull(client.Socket, StatusMessage.BANNED);
                            OnPunished?.Invoke(this, new ServerPunishmentEventArgs(client, PunishmentType.BAN, DateTime.Now, client.PunishmentReason));
                        } else if (client.IsKicked)
                        {
                            SendIfNotNull(client.Socket, StatusMessage.KICKED);
                            OnPunished?.Invoke(this, new ServerPunishmentEventArgs(client, PunishmentType.KICK, DateTime.Now, client.PunishmentReason));
                        } else if (client.IsMuted)
                        {
                            SendIfNotNull(client.Socket, StatusMessage.MUTED);
                            OnPunished?.Invoke(this, new ServerPunishmentEventArgs(client, PunishmentType.MUTE, DateTime.Now, client.PunishmentReason));
                        }

                        client.Socket.Close();
                    }

                    byte[]? relayByte = NSP2Util.GeneratePacket(new NSP2Response()
                    {
                        Message = JsonConvert.SerializeObject(client.ToUser(UseAddressProtection)),
                        Result = StatusMessage.DISCONNECTED_EVENT
                    }, PasswordKey, UseCompression, true);

                    lock (_ClientManagerLock)
                    {
                        foreach (NSP2ServerClient cli in Clients)
                        {
                            SendIfNotNull(cli.Socket, relayByte);
                        }
                    }
                    OnClientDisconnected?.Invoke(this, new ClientDisconnectEventArgs(client.ToUser(), DateTime.Now));
                }
                lock (_ClientManagerLock)
                {
                    _ClientManagers.Remove(client);
                }
            }   
        }

        /// https://stackoverflow.com/questions/4238345/asynchronously-wait-for-taskt-to-complete-with-timeout
        private static async Task<TResult> TimeoutAfter<TResult>(Task<TResult> task, TimeSpan timeout)
        {

            using (var timeoutCancellationTokenSource = new CancellationTokenSource())
            {

                var completedTask = await Task.WhenAny(task, Task.Delay(timeout, timeoutCancellationTokenSource.Token));
                if (completedTask == task)
                {
                    timeoutCancellationTokenSource.Cancel();
                    return await task;  // Very important in order to propagate exceptions
                } else
                {
                    throw new TimeoutException("The operation has timed out.");
                }
            }
        }

        public void Broadcast(byte[] resBytes)
        {
            lock (_ClientManagerLock)
            {
                foreach (NSP2ServerClient client in Clients)
                {
                    SendIfNotNull(client.Socket, resBytes);
                }
            }
        }

        public void Broadcast<T>(T res)
        {
            byte[]? resBytes = NSP2Util.GeneratePacket(res, PasswordKey, UseCompression);
            if (resBytes == null)
                return;
            lock (_ClientManagerLock)
            {
                foreach (NSP2ServerClient client in Clients)
                {
                    SendIfNotNull(client.Socket, resBytes);
                }
            }
        }

        public NSP2ServerClient? GetClient(string idIP)
        {
            lock (_ClientManagerLock)
            {
                foreach (NSP2ServerClient client in Clients)
                {
                    if (NSP2Util.IsID(idIP))
                    {
                        if (client.ID.Equals(idIP))
                        {
                            return client;
                        }
                    }
                    else
                    {
                        if (client.IP.Equals(idIP))
                        {
                            return client;
                        }
                    }
                }
            }
            return null;
        }

        public bool SendMessage(NSP2ServerClient client, byte[] resBytes)
        {
            try
            {
                if (!client.IsConnected)
                    return false;
                SendIfNotNull(client.Socket, resBytes);
                return true;
            } catch (Exception)
            {
                return false;
            }
        }

        public bool SendMessage<T>(NSP2ServerClient client, T res)
        {
            try
            {
                if (!client.IsConnected)
                    return false;
                byte[]? resBytes = NSP2Util.GeneratePacket(res, PasswordKey, UseCompression);
                if (resBytes == null)
                    return false;
                SendIfNotNull(client.Socket, resBytes);
                return true;
            } catch (Exception)
            {
                return false;
            }
        }

        public bool SendMessage(string idIP, byte[] resBytes)
        {
            NSP2ServerClient? cli = GetClient(idIP);
            if (cli == null)
                return false;
            return SendMessage(cli, resBytes);
        }

        public bool SendMessage<T>(string idIP, T res)
        {
            NSP2ServerClient? cli = GetClient(idIP);
            if (cli == null)
                return false;
            return SendMessage(cli, res);
        }

        private void HandleListenClientThread()
        {
            if (IPObject == null)
                return;

            if (_Socket != null)
                return;

            _Socket = new TcpListener(IPObject, Port);
            _Socket.Start();
            IsRunning = true;
            StartTime = DateTime.Now;

            while (IsRunning)
            {
                TcpClient clientSocket;
                try
                {
                    Task<TcpClient> task = _Socket.AcceptTcpClientAsync().WaitAsync(TimeSpan.FromSeconds(5));
                    task.Wait();

                    if (task.Status != TaskStatus.RanToCompletion)
                        continue;

                    clientSocket = task.Result;
                }
                catch (Exception ex)
                {
                    if (ex.InnerException is SocketException)
                        break;
                    continue;
                }

                lock (_ClientManagerLock)
                {
                    NSP2ServerClient cli = new NSP2ServerClient(clientSocket, GetNextID(), DefaultPermissions);
                    Thread thread = new Thread(new ThreadStart(HandleClientThread));

                    _ClientManagers.Add(cli, new MutableKeyValuePair<Thread, ClientState>(thread, ClientState.HANDSHAKE));
                    _ClientManagers[cli].Key.Start();
                }
            }

            _Socket.Stop();
            _Socket = null;
            IsRunning = false;
            StartTime = new DateTime();
        }

        public void Start()
        {
            if (!IsRunning)
            {
                _AcceptThread = new Thread(HandleListenClientThread);
                _AcceptThread.Start();
                IsRunning = true;
                OnServerStarted?.Invoke(this, new ServerModifyEventArgs(this, DateTime.Now));
            }
        }

        public void Stop()
        {
            if (IsRunning)
            {
                lock (_ClientManagerLock)
                {
                    foreach (NSP2ServerClient client in Clients)
                    {
                        client.Kick();
                    }
                }
                DateTime expire = DateTime.Now + TimeSpan.FromSeconds(5);
                IsRunning = false;

                while (_Socket != null && DateTime.Now < expire)
                {
                    Thread.SpinWait(1);
                }
                _AcceptThread = null;
                OnServerStopped?.Invoke(this, new ServerModifyEventArgs(this, DateTime.Now));
            }
        }

        public class ClientDisconnectEventArgs : EventArgs
        {
            public DateTime Time { get; }
            public NSP2ConnectedUser Client { get; }

            public ClientDisconnectEventArgs(NSP2ConnectedUser client, DateTime time)
            {
                Time = time;
                Client = client;
            }
        }

        public class ClientMessageReceivedEventArgs : EventArgs
        {
            public DateTime Time { get; }
            public NSP2ServerClient Client { get; }
            public NSP2Response Response { get; }

            public ClientMessageReceivedEventArgs(NSP2ServerClient client, NSP2Response response, DateTime time)
            {
                Time = time;
                Client = client;
                Response = response;
            }
        }

        public class ServerModifyEventArgs : EventArgs
        {
            public DateTime Time { get; }

            public NSP2Server Server { get; }

            public ServerModifyEventArgs(NSP2Server server, DateTime time)
            {
                Server = server;
                Time = time;
            }
        }
    }
}
