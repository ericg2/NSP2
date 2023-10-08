using NSP2.Server;
using NSP2Lib.Client;
using System.Net.Sockets;

namespace NSP2Example
{
    internal class Program
    {
        static void Main(string[] args)
        {
            NSP2Server server = new NSP2Server();
            server.Start();

            server.OnClientConnected += Server_OnClientConnected;
            
            for (int i=0; i<10; i++)
            {
                new NSP2Client("192.168.1.149", 8080).Start();
            }
        
        }

        private static void Server_OnClientConnected(object? sender, NSP2ServerClient.ServerClientEventArgs e)
        {
            Console.WriteLine("Client connected!");

        }
    }
}