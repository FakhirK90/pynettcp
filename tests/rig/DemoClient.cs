// A stock WCF client for the demo service, used to generate reference traffic.
//
// Pointed at the relay in tools/tap.py rather than straight at the service, so
// the exact MC-NMF preamble and record sequence a real NetTcpBinding client
// emits can be observed and diffed against pynettcp's.
//
//   DemoClient.exe [port] [None|Transport] [calls]

using System;
using System.ServiceModel;

namespace PyNetTcpDemo
{
    [ServiceContract(Namespace = "urn:DemoService")]
    public interface IDemoService
    {
        [OperationContract]
        string Echo(string text);

        [OperationContract]
        int Add(int a, int b);
    }

    public static class ClientProgram
    {
        public static int Main(string[] args)
        {
            int port = args.Length > 0 ? int.Parse(args[0]) : 8899;
            SecurityMode mode = args.Length > 1 && args[1] == "Transport"
                ? SecurityMode.Transport
                : SecurityMode.None;
            int calls = args.Length > 2 ? int.Parse(args[2]) : 1;

            var binding = new NetTcpBinding(mode);
            var address = new EndpointAddress("net.tcp://localhost:" + port + "/Demo");
            var factory = new ChannelFactory<IDemoService>(binding, address);

            try
            {
                var channel = factory.CreateChannel();
                for (int i = 0; i < calls; i++)
                {
                    // Several calls on one channel, so session-dictionary reuse
                    // shows up in the capture as well as the first-message block.
                    Console.WriteLine("Echo -> " + channel.Echo("hello" + i));
                }
                ((IClientChannel)channel).Close();
                factory.Close();
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("CLIENT FAILED " + ex.GetType().Name + ": " + ex.Message);
                return 1;
            }
        }
    }
}
