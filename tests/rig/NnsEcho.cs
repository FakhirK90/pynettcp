// A bare System.Net.Security.NegotiateStream echo server.
//
// WCF drops the connection without explanation when a NegotiateStream frame is
// wrong, which makes [MS-NNS] bugs almost undebuggable. This strips WCF away
// so the failure surfaces as an actual .NET exception message.
//
// Protocol once authenticated: length-prefixed echo, [len:4 LE][bytes], which
// travels inside NegotiateStream's own framing exactly as WCF's records do.
//
//   NnsEcho.exe [port]

using System;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text;

namespace PyNetTcpDemo
{
    public static class NnsEchoProgram
    {
        public static int Main(string[] args)
        {
            int port = args.Length > 0 ? int.Parse(args[0]) : 8896;

            var listener = new TcpListener(IPAddress.Loopback, port);
            listener.Start();
            Console.WriteLine("READY nns://localhost:" + port);
            Console.Out.Flush();

            while (true)
            {
                using (TcpClient client = listener.AcceptTcpClient())
                using (var negotiate = new NegotiateStream(client.GetStream(), false))
                {
                    try
                    {
                        negotiate.AuthenticateAsServer(
                            (NetworkCredential)CredentialCache.DefaultCredentials,
                            ProtectionLevel.EncryptAndSign,
                            TokenImpersonationLevel.Identification);

                        var identity = (IIdentity)negotiate.RemoteIdentity;
                        Console.WriteLine("AUTH ok user=" + identity.Name
                            + " type=" + identity.AuthenticationType
                            + " encrypted=" + negotiate.IsEncrypted
                            + " signed=" + negotiate.IsSigned);
                        Console.Out.Flush();

                        var header = new byte[4];
                        while (ReadExact(negotiate, header, 4))
                        {
                            int length = BitConverter.ToInt32(header, 0);
                            var payload = new byte[length];
                            if (!ReadExact(negotiate, payload, length))
                                break;

                            Console.WriteLine("RECV " + length + " bytes: "
                                + BitConverter.ToString(payload));
                            Console.Out.Flush();

                            negotiate.Write(header, 0, 4);
                            negotiate.Write(payload, 0, length);
                            negotiate.Flush();
                        }
                        Console.WriteLine("CLOSED");
                    }
                    catch (Exception ex)
                    {
                        // The whole point of this rig.
                        Console.WriteLine("ERROR " + ex.GetType().FullName + ": " + ex.Message);
                        if (ex.InnerException != null)
                            Console.WriteLine("INNER " + ex.InnerException.GetType().FullName
                                + ": " + ex.InnerException.Message);
                    }
                    Console.Out.Flush();
                }
            }
        }

        private static bool ReadExact(NegotiateStream stream, byte[] buffer, int count)
        {
            int offset = 0;
            while (offset < count)
            {
                int read = stream.Read(buffer, offset, count - offset);
                if (read <= 0) return false;
                offset += read;
            }
            return true;
        }
    }
}
