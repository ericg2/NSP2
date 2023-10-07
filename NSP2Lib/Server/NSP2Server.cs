/**
 *  
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

using Microsoft.VisualBasic;
using Newtonsoft.Json;
using NSP2.Client;
using NSP2.JSON;
using NSP2.JSON.Message;
using NSP2.Util;
using System.Collections;
using System.Net;
using System.Net.Sockets;
using System.Reflection.Metadata.Ecma335;
using System.Security.Cryptography;
using static NSP2.JSON.Message.UpdatePermissionTemplate;
using static NSP2.JSON.Message.UserReferenceTemplate;
using static NSP2.JSON.NSP2Request;
using static NSP2.JSON.NSP2Response;
using static NSP2.Server.NSP2ServerClient;
using static NSP2.Server.NSP2ServerClient.PunishmentEventArgs;

namespace NSP2.Server
{
    public class NSP2Server
    {
        [JsonIgnore]
        public static readonly int UNLIMITED = -1;

        public int Port { set; get; } = 8080;

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

        public NSP2PermissionList DefaultPermissions { set; get; } = new NSP2PermissionList();

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
        public List<NSP2ServerClient> Clients { private set; get; } = new List<NSP2ServerClient>();

        public event EventHandler<ClientMessageReceivedEventArgs>? OnMessageReceived;

        public event EventHandler<ClientEventArgs>? OnClientConnected;

        public event EventHandler<ClientDisconnectEventArgs>? OnClientDisconnected;

        public event EventHandler<PunishmentEventArgs>? OnPunished;

        public event EventHandler<ClientEventArgs>? OnMuteRemoved;

        ////////////////////////////////////////////////////////////////

        private Dictionary<string, Thread> _ClientManagers = new Dictionary<string, Thread>();
        private Dictionary<TcpClient, Thread> _AcceptorThreads = new Dictionary<TcpClient, Thread>();

        private Thread? _AcceptThread = null;
        private TcpListener? _Socket = null;

        private object _ClientManagerLock = new object();
        private object _ClientListLock = new object();
        private object _AccountListLock = new object();
        private object _AcceptThreadLock = new object();

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
                lock (_ClientListLock)
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

        private StatusResponseTemplate GenerateStatusResponse(bool viewClients)
        {
            List<NSP2ConnectedUser> users = new List<NSP2ConnectedUser>();

            if (viewClients)
            {
                lock (_ClientListLock)
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
                DefaultPermissions = this.DefaultPermissions,
                Uptime = this.Uptime,
                Clients = viewClients ? users : null
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

        private void SendIfNotNull(TcpClient sock, StatusMessage message, bool useServerSettings=true)
        {
            byte[]? passwordKey = useServerSettings ? PasswordKey : null;
            bool compression = useServerSettings ? UseCompression : false;

            SendIfNotNull(sock, NSP2Util.GeneratePacket(new NSP2Response()
            {
                SentBy = null,
                Result = message
            }, passwordKey, compression, false));
        }

        private int[] GetClientIndex(string reference, UpdateType type)
        {
            bool isID = false;

            if (reference.Substring(0, 2).ToUpper().Equals("ID"))
                isID = true;

            List<int> indexes = new List<int>();

            for (int i=0; i<Clients.Count; i++)
            {
                if (type == UpdateType.ID_IP)
                {
                    if (isID)
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

        private void HandleClientThread(string id)
        {
            NSP2ServerClient? client = null;

            while (true)
            {
                client = null;

                lock (_ClientListLock)
                {
                    foreach (NSP2ServerClient cli in Clients)
                    {
                        if (cli.ID.Equals(id))
                        {
                            client = cli;
                            break;
                        }
                    }
                }

                if (client == null || !client.IsConnected)
                    break;

                if (client.IsBanned || client.IsKicked)
                    break;

                bool loopBack;
                byte[]? packetBytes = NSP2Util.ReceivePacketBytes(client.Socket, out loopBack, PasswordKey, UseCompression, TimeSpan.FromSeconds(5));

                if (packetBytes == null)
                    continue;

                if (loopBack)
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
                                    Message = req.Message,
                                    SentBy = client.ToUser()
                                }, PasswordKey, UseCompression, true);

                                if (relayBytes == null)
                                    break;

                                lock (_ClientListLock)
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
                                SendIfNotNull(client.Socket,
                                        NSP2Util.GeneratePacket(GenerateStatusResponse(
                                            client.Permissions.IsAdminOr(NSP2Permission.VIEW_CLIENTS)),
                                            PasswordKey,
                                            UseCompression,
                                            false
                                    ));
                                break;
                            }
                        case RequestAction.UPDATE_PERMISSION:
                            {
                                // Only admins can use this feature.
                                if (!client.Permissions.IsAdmin())
                                {
                                    SendIfNotNull(client.Socket, StatusMessage.NO_PERMISSION);
                                }

                                // Check if message can decode to UpdatePermissionTemplate.
                                UpdatePermissionTemplate? perm = JsonConvert.DeserializeObject<UpdatePermissionTemplate>(req.Message);

                                if (perm == null || NSP2Util.IsDefault<UpdatePermissionTemplate>(perm))
                                {
                                    // Decoding failed. Return failure.
                                    SendIfNotNull(client.Socket, StatusMessage.DECODE_FAIL);
                                    break;
                                }

                                // Attempt to update permissions.
                                bool success = false;
                                lock (_ClientListLock)
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

                                SendIfNotNull(client.Socket, success ? StatusMessage.SUCCESS : StatusMessage.FAILURE);
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
                                    SendIfNotNull(client.Socket, StatusMessage.NO_PERMISSION);
                                    break;
                                }

                                PunishTemplate? user = JsonConvert.DeserializeObject<PunishTemplate>(req.Message);

                                if (user == null || NSP2Util.IsDefault<PunishTemplate>(user))
                                {
                                    SendIfNotNull(client.Socket, StatusMessage.DECODE_FAIL);
                                    break;
                                }

                                bool success = false;
                                lock (_ClientListLock)
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

                                SendIfNotNull(client.Socket, success ? StatusMessage.SUCCESS : StatusMessage.FAILURE);
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
                                    SendIfNotNull(client.Socket, StatusMessage.NO_PERMISSION);
                                    break;
                                }

                                UserReferenceTemplate? user = JsonConvert.DeserializeObject<UserReferenceTemplate>(req.Message);

                                if (user == null || NSP2Util.IsDefault<UserReferenceTemplate>(user))
                                {
                                    SendIfNotNull(client.Socket, StatusMessage.DECODE_FAIL);
                                    break;
                                }

                                bool success = false;
                                lock (_ClientListLock)
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

                                    SendIfNotNull(client.Socket, success ? StatusMessage.SUCCESS : StatusMessage.FAILURE);
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
                if (client.IsConnected)
                {
                    if (client.IsBanned)
                    {
                        SendIfNotNull(client.Socket, StatusMessage.BANNED);
                        OnPunished?.Invoke(this, new PunishmentEventArgs(client, PunishmentType.BAN, DateTime.Now, client.PunishmentReason)); 
                    }
                        
                    else if (client.IsKicked)
                    {
                        SendIfNotNull(client.Socket, StatusMessage.KICKED);
                        OnPunished?.Invoke(this, new PunishmentEventArgs(client, PunishmentType.KICK, DateTime.Now, client.PunishmentReason));
                    }
                    else if (client.IsMuted)
                    {
                        SendIfNotNull(client.Socket, StatusMessage.MUTED);
                        OnPunished?.Invoke(this, new PunishmentEventArgs(client, PunishmentType.MUTE, DateTime.Now, client.PunishmentReason));
                    }                  

                    client.Socket.Close();
                }

                lock (_ClientListLock)
                {
                    Clients.Remove(client);
                }

                lock (_ClientManagerLock)
                {
                    _ClientManagers.Remove(client.ID);
                }

                OnClientDisconnected?.Invoke(this, new ClientDisconnectEventArgs(client.ToUser(), DateTime.Now));
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

        /// <summary>
        /// Offload the task of listening and accepting the client to a seperate Thread for increased performance.
        /// </summary>
        private void HandleAcceptClientThread()
        {
            TcpClient? socket = null;
            DateTime expire = DateTime.Now.AddMinutes(1);
            DateTime nextSend = DateTime.Now; // periodically re-send the handshake data on the event of no response.
            bool noResponse = true;

            while (DateTime.Now <= expire)
            {
                lock (_AcceptThreadLock)
                {
                    foreach (KeyValuePair<TcpClient, Thread> kvp in _AcceptorThreads)
                    {
                        if (kvp.Value.ManagedThreadId == Thread.CurrentThread.ManagedThreadId)
                        {
                            socket = kvp.Key;
                            break;
                        }
                    }
                }
                
                if (socket == null || !socket.Connected)
                    break;

                if (noResponse && DateTime.Now >= nextSend)
                {
                    // Use no encryption since the client did not acknowledge.
                    byte[]? packet = NSP2Util.GeneratePacket(GenerateStatusResponse(DefaultPermissions.IsAdminOr(NSP2Permission.VIEW_CLIENTS)));
                    SendIfNotNull(socket, packet);
                    nextSend = DateTime.Now.AddSeconds(10);
                }

                byte[]? packetBytes = NSP2Util.ReceivePacketBytes(socket, out _, PasswordKey, UseCompression, TimeSpan.FromSeconds(5));
                if (packetBytes == null)
                    continue;

                NSP2Request? req = JsonConvert.DeserializeObject<NSP2Request>(NSP2Util.ENCODING.GetString(packetBytes));

                if (req == null)
                    continue;

                if (req.Type == RequestAction.DISCONNECT)
                    break; // disconnect

                if (req.Type != RequestAction.AUTHENTICATE)
                {
                    // No other operations are supported at this moment, except Authenticate.
                    SendIfNotNull(socket, StatusMessage.DECODE_FAIL, false);
                    continue;
                }

                noResponse = false;

                /********************************* ACKNOWLEDGEMENT SUCCESSFUL ************************/

                NSP2ServerClient client = new NSP2ServerClient(socket, GetNextID(), DefaultPermissions);

                // Attempt to decode the message template. This is NOT required, but allows for additional permissions.
                AuthTemplate? auth = JsonConvert.DeserializeObject<AuthTemplate>(req.Message);

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
                    }
                    catch (Exception)
                    {
                        SendIfNotNull(socket, StatusMessage.HANDSHAKE_FAIL, true);
                    }
                }

                // Send a success packet, then add the user.
                SendIfNotNull(socket, StatusMessage.SUCCESS);

                lock (_ClientListLock)
                {
                    Clients.Add(client);
                }

                lock (_ClientManagerLock)
                {
                    _ClientManagers.Add(client.ID, new Thread(() =>
                    {
                        HandleClientThread(client.ID);
                    }));
                    _ClientManagers[client.ID].Start();
                    OnClientConnected?.Invoke(this, new ClientEventArgs(client, DateTime.Now));
                    break; 
                }
            }

            lock (_AcceptThreadLock)
            {
                TcpClient? key = null;
                foreach (KeyValuePair<TcpClient, Thread> kvp in _AcceptorThreads)
                {
                    if (kvp.Value.ManagedThreadId.Equals(Thread.CurrentThread.ManagedThreadId))
                    {
                        key = kvp.Key;
                        break;
                    }
                }
                if (key != null)
                    _AcceptorThreads.Remove(key);
            }
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

            while (IsRunning)
            {
                TcpClient clientSocket;
                try
                {
                    Task<TcpClient> task = TimeoutAfter(_Socket.AcceptTcpClientAsync(), TimeSpan.FromSeconds(5));
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

                lock (_AcceptThreadLock)
                {
                    string id = GetNextID();
                    _AcceptorThreads.Add(clientSocket, new Thread(new ThreadStart(HandleAcceptClientThread)));
                    _AcceptorThreads[clientSocket].Start();
                }
            }

            _Socket.Stop();
            _Socket = null;
            IsRunning = false;
        }

        public void Start()
        {
            if (!IsRunning)
            {
                _AcceptThread = new Thread(HandleListenClientThread);
                _AcceptThread.Start();
                IsRunning = true;
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
    }
}
