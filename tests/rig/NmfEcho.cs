// A minimal MC-NMF server that performs the NegotiateStream upgrade and then
// prints every byte it decrypts.
//
// WCF reports a bad secured frame as a bare connection reset, which makes it
// impossible to tell "the crypto is wrong" from "the record after it is
// wrong". This rig reproduces WCF's upgrade sequence but is completely
// transparent about what arrives, so the two can be told apart.
//
//   NmfEcho.exe [port]
//
// Reads: Version, Mode, Via, KnownEncoding, UpgradeRequest
// Sends: UpgradeResponse, authenticates as server, then dumps decrypted bytes.

using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text;

namespace PyNetTcpDemo
{
    public static class NmfEchoProgram
    {
        const byte Version = 0x00;
        const byte ModeRecord = 0x01;
        const byte Via = 0x02;
        const byte KnownEncoding = 0x03;
        const byte PreambleEnd = 0x0C;
        const byte PreambleAck = 0x0B;
        const byte UpgradeRequest = 0x09;
        const byte UpgradeResponse = 0x0A;

        public static int Main(string[] args)
        {
            int port = args.Length > 0 ? int.Parse(args[0]) : 8895;
            var listener = new TcpListener(IPAddress.Loopback, port);
            listener.Start();
            Console.WriteLine("READY net.tcp://localhost:" + port + "/Demo");
            Console.Out.Flush();

            while (true)
            {
                using (TcpClient client = listener.AcceptTcpClient())
                {
                    try
                    {
                        Handle(client);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("ERROR " + ex.GetType().FullName + ": " + ex.Message);
                        if (ex.InnerException != null)
                            Console.WriteLine("INNER " + ex.InnerException.GetType().FullName
                                + ": " + ex.InnerException.Message);
                    }
                    Console.Out.Flush();
                }
            }
        }

        static void Handle(TcpClient client)
        {
            NetworkStream raw = client.GetStream();

            // -- preamble ---------------------------------------------------
            Expect(raw, Version, "Version");
            raw.ReadByte(); raw.ReadByte();               // major, minor
            Expect(raw, ModeRecord, "Mode");
            Console.WriteLine("MODE 0x" + raw.ReadByte().ToString("x2"));

            Expect(raw, Via, "Via");
            Console.WriteLine("VIA " + ReadString(raw));

            Expect(raw, KnownEncoding, "KnownEncoding");
            Console.WriteLine("ENCODING 0x" + raw.ReadByte().ToString("x2"));

            int next = raw.ReadByte();
            if (next != UpgradeRequest)
            {
                Console.WriteLine("NO UPGRADE, next record 0x" + next.ToString("x2"));
                return;
            }
            Console.WriteLine("UPGRADE " + ReadString(raw));

            raw.WriteByte(UpgradeResponse);
            raw.Flush();
            Console.WriteLine("SENT UpgradeResponse");
            Console.Out.Flush();

            // -- authenticate ----------------------------------------------
            var negotiate = new NegotiateStream(raw, false);
            negotiate.AuthenticateAsServer(
                (NetworkCredential)CredentialCache.DefaultCredentials,
                ProtectionLevel.EncryptAndSign,
                TokenImpersonationLevel.Identification);

            var identity = (IIdentity)negotiate.RemoteIdentity;
            Console.WriteLine("AUTH ok user=" + identity.Name
                + " type=" + identity.AuthenticationType
                + " encrypted=" + negotiate.IsEncrypted);
            Console.Out.Flush();

            // -- decrypted framing -----------------------------------------
            int record = negotiate.ReadByte();
            Console.WriteLine("FIRST DECRYPTED BYTE 0x" + record.ToString("x2")
                + (record == PreambleEnd ? "  (PreambleEnd -- correct)" : "  (EXPECTED 0x0c)"));
            Console.Out.Flush();

            if (record != PreambleEnd)
                return;

            negotiate.WriteByte(PreambleAck);
            negotiate.Flush();
            Console.WriteLine("SENT PreambleAck");

            // Dump whatever framing records follow, without interpreting them.
            var buffer = new byte[4096];
            int read;
            while ((read = negotiate.Read(buffer, 0, buffer.Length)) > 0)
            {
                Console.WriteLine("DECRYPTED " + read + " bytes: "
                    + BitConverter.ToString(buffer, 0, Math.Min(read, 32)));
                Console.Out.Flush();
            }
            Console.WriteLine("CLOSED");
        }

        static void Expect(Stream stream, byte expected, string name)
        {
            int actual = stream.ReadByte();
            if (actual != expected)
                throw new InvalidDataException(
                    "expected " + name + " (0x" + expected.ToString("x2")
                    + "), got 0x" + actual.ToString("x2"));
        }

        static string ReadString(Stream stream)
        {
            int length = 0, shift = 0, b;
            do
            {
                b = stream.ReadByte();
                length |= (b & 0x7F) << shift;
                shift += 7;
            } while ((b & 0x80) != 0);

            var bytes = new byte[length];
            int offset = 0;
            while (offset < length)
                offset += stream.Read(bytes, offset, length - offset);
            return Encoding.UTF8.GetString(bytes);
        }
    }
}
