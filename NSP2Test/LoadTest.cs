using NSP2.JSON;
using NSP2.Server;
using NSP2Lib.Client;
using NUnit.Framework;
using static NSP2.JSON.NSP2Request;
using static NSP2.JSON.NSP2Response;

namespace NSP2Test
{
    public class LoadTest
    {
        private NSP2Server? _Server;

        private static readonly int MAX_CLIENTS = 100;
        private static readonly int MAX_MESSAGES = 10;

        [SetUp]
        public void Initialize()
        {
            if (_Server == null)
            {
                _Server = new NSP2Server();
                _Server.Start();
            }
        }

        [TearDown]
        public void Shutdown()
        {
            if (_Server != null)
            {
                _Server.Stop();
                _Server = null;
            }
        }

        private bool RunLoadTest(out string? msg)
        {
            msg = null;

            int connected = 0;
            int messagesReceived = 0;
            bool drewLine = false;

            if (_Server == null)
            {
                msg = "Server is null or invalid!";
                return false;
            }

            _Server.OnClientConnected += (o, i) =>
            {
                connected++;
                TestContext.Out.WriteLine(connected + " / " + MAX_CLIENTS + " connected.");
            };

            _Server.OnMessageReceived += (o, i) =>
            {
                if (!drewLine)
                {
                    TestContext.Out.WriteLine("***********************************************");
                    drewLine = true;
                }
                TestContext.Out.WriteLine(messagesReceived + " / " + (MAX_CLIENTS * MAX_MESSAGES));
                messagesReceived++;
            };

            List<NSP2Client> clients = new List<NSP2Client>();

            for (int i=0; i<MAX_CLIENTS; i++)
            {
                NSP2Client client = new NSP2Client(_Server.IP, _Server.Port);
                if (!client.Start(TimeSpan.FromSeconds(5)))
                {
                    msg = "Client " + i + " failed to connect.";
                    return false;
                }
                clients.Add(client);
                Thread.Sleep(500);
            }

            Thread.Sleep(3000);

            if (_Server.Clients.Count != MAX_CLIENTS)
            {
                msg = "Only " + clients.Count + " / " + MAX_CLIENTS + " connected in time-frame.";
                return false;
            }

            // Send messages in each Client.
            for (int i=0; i<MAX_MESSAGES; i++)
            {
                foreach (NSP2ServerClient client in _Server.Clients)
                {
                    _Server.SendMessage(client, new NSP2Response()
                    {
                        SentBy = null,
                        Message = "Hello",
                        Result = StatusMessage.MESSAGE_RECEIVE
                    });
                }
            }

            Thread.Sleep(3000);

            if (messagesReceived != (MAX_CLIENTS * MAX_MESSAGES))
            {
                msg = "Only " + messagesReceived + " / " + (MAX_CLIENTS * MAX_MESSAGES) + " were received.";
                return false;
            }

            // Kick all clients if successful.
            foreach (NSP2ServerClient client in _Server.Clients)
            {
                client.Kick();
            }

            Thread.Sleep(5000);

            if (_Server.Clients.Count != 0)
            {
                msg = _Server.Clients.Count + " clients connected, expected zero after kick.";
                return false;
            }

            return true;
        }

        [Test(Description = "Connects hundreds of clients, performing I/O operations. No encryption/compression")]
        public void ClientTestNoEncryptionOrCompression()
        {
            string? msg;
            bool result = RunLoadTest(out msg);
            Assert.IsTrue(result, msg);
        }
    }
}
