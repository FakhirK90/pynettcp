// A throwaway WCF service used purely as a test target for pynettcp.
//
// It exists so the library is never pointed at anyone's real service. Nothing
// here talks to a database or any external system: every operation is pure.
//
// Security mode is chosen at startup so each protocol layer can be brought up
// in isolation -- None first (framing + encoding only), then Transport once
// the NegotiateStream layer exists.
//
//   DemoService.exe [port] [None|Transport]
//
// Prints READY on a line of its own once the endpoint is listening, so a test
// harness can wait for it deterministically instead of sleeping.

using System;
using System.Runtime.Serialization;
using System.ServiceModel;
using System.ServiceModel.Description;

namespace PyNetTcpDemo
{
    [DataContract(Namespace = "urn:DemoService")]
    public class LeaveRequest
    {
        [DataMember(Order = 0)] public string EmployeeId { get; set; }
        [DataMember(Order = 1)] public string ReasonText { get; set; }
        [DataMember(Order = 2)] public int TotalDays { get; set; }
        [DataMember(Order = 3)] public DateTime FromDate { get; set; }
    }

    [DataContract(Namespace = "urn:DemoService")]
    public class LeaveResult
    {
        [DataMember(Order = 0)] public string Reference { get; set; }
        [DataMember(Order = 1)] public bool Accepted { get; set; }
    }

    // ---- the awkward shapes real contracts use -------------------------------
    // Everything below exists to exercise a construct the simple operations
    // never reach: enums, arrays of scalars and of complex types, nesting,
    // decimal, Guid, TimeSpan, nullable value types and typed faults.

    [DataContract(Namespace = "urn:DemoService")]
    public enum OrderStatus
    {
        [EnumMember] Draft,
        [EnumMember] Submitted,
        [EnumMember] Approved,
    }

    [DataContract(Namespace = "urn:DemoService")]
    public class Address
    {
        [DataMember(Order = 0)] public string Street { get; set; }
        [DataMember(Order = 1)] public string City { get; set; }
    }

    [DataContract(Namespace = "urn:DemoService")]
    public class OrderLine
    {
        [DataMember(Order = 0)] public string Sku { get; set; }
        [DataMember(Order = 1)] public int Quantity { get; set; }
        [DataMember(Order = 2)] public decimal UnitPrice { get; set; }
    }

    [DataContract(Namespace = "urn:DemoService")]
    public class Order
    {
        [DataMember(Order = 0)] public Guid Id { get; set; }
        [DataMember(Order = 1)] public OrderStatus Status { get; set; }
        [DataMember(Order = 2)] public Address ShipTo { get; set; }          // nested
        [DataMember(Order = 3)] public OrderLine[] Lines { get; set; }       // complex array
        [DataMember(Order = 4)] public string[] Tags { get; set; }           // scalar array
        [DataMember(Order = 5)] public decimal Total { get; set; }
        [DataMember(Order = 6)] public TimeSpan LeadTime { get; set; }
        [DataMember(Order = 7)] public int? Priority { get; set; }           // nullable
        [DataMember(Order = 8)] public DateTime CreatedUtc { get; set; }
    }

    [DataContract(Namespace = "urn:DemoService")]
    public class ValidationFault
    {
        [DataMember(Order = 0)] public string Code { get; set; }
        [DataMember(Order = 1)] public string[] Problems { get; set; }
    }

    // Mirrors how Dynamics AX carries CallContext: a DataContract in its *own*
    // namespace, attached to the message as a SOAP header rather than as a body
    // parameter. Header support has to be exercised against this shape, since a
    // header is declared in wsdl:binding, not in the portType.
    [DataContract(Namespace = "urn:DemoService/ctx")]
    public class DemoContext
    {
        [DataMember(Order = 0)] public string Company { get; set; }
        [DataMember(Order = 1)] public string Language { get; set; }
    }

    [MessageContract(IsWrapped = true, WrapperName = "PlaceOrder", WrapperNamespace = "urn:DemoService")]
    public class PlaceOrderRequest
    {
        [MessageHeader(Namespace = "urn:DemoService/ctx")]
        public DemoContext Context;

        [MessageBodyMember(Order = 0, Namespace = "urn:DemoService")]
        public string ItemId;

        [MessageBodyMember(Order = 1, Namespace = "urn:DemoService")]
        public int Quantity;
    }

    [MessageContract(IsWrapped = true, WrapperName = "PlaceOrderResponse", WrapperNamespace = "urn:DemoService")]
    public class PlaceOrderResponse
    {
        [MessageBodyMember(Order = 0, Namespace = "urn:DemoService")]
        public string Confirmation;
    }

    [ServiceContract(Namespace = "urn:DemoService")]
    public interface IDemoService
    {
        // Echoes the header back inside the body, so a test can prove the
        // header actually arrived rather than merely that the call succeeded.
        [OperationContract]
        PlaceOrderResponse PlaceOrder(PlaceOrderRequest request);

        [OperationContract]
        string Echo(string text);

        [OperationContract]
        int Add(int a, int b);

        [OperationContract]
        LeaveResult CreateLeave(LeaveRequest request);

        // Exercises the fault path so faults.py has something real to parse.
        [OperationContract]
        void Fail(string reason);

        // Exercises message sizes past the encoder's buffering thresholds.
        [OperationContract]
        string EchoLarge(int size);

        // Round-trips every awkward type at once, so a mismatch in any one of
        // them shows up as a changed field rather than a vague failure.
        [OperationContract]
        Order SubmitOrder(Order order);

        // An array return, including an empty one.
        [OperationContract]
        Order[] ListOrders(int count);

        // A typed fault carrying structured detail, as AifFault does.
        [OperationContract]
        [FaultContract(typeof(ValidationFault))]
        void ValidateOrder(Order order);
    }

    // AddressFilterMode.Any so the service still answers when reached through
    // the relay in tools/tap.py, whose port differs from the one the client
    // puts in the WS-Addressing To header.
    [ServiceBehavior(AddressFilterMode = AddressFilterMode.Any)]
    public class DemoService : IDemoService
    {
        public string Echo(string text)
        {
            return text;
        }

        public int Add(int a, int b)
        {
            return a + b;
        }

        public LeaveResult CreateLeave(LeaveRequest request)
        {
            if (request == null)
                throw new FaultException("request was null");

            return new LeaveResult
            {
                Reference = "LV-" + request.EmployeeId + "-" + request.TotalDays,
                Accepted = request.TotalDays > 0
            };
        }

        public void Fail(string reason)
        {
            throw new FaultException(reason ?? "unspecified");
        }

        public string EchoLarge(int size)
        {
            return new string('x', size);
        }

        public Order SubmitOrder(Order order)
        {
            if (order == null)
                throw new FaultException("order was null");

            // Echo it back with two observable changes, so the test can tell a
            // real round trip from a coincidence.
            order.Status = OrderStatus.Submitted;
            order.Total = 0m;
            if (order.Lines != null)
                foreach (var line in order.Lines)
                    order.Total += line.UnitPrice * line.Quantity;

            return order;
        }

        public Order[] ListOrders(int count)
        {
            var orders = new Order[count];
            for (int i = 0; i < count; i++)
            {
                orders[i] = new Order
                {
                    Id = Guid.Empty,
                    Status = OrderStatus.Draft,
                    Tags = new[] { "bulk", "generated" },
                    Lines = new[] { new OrderLine { Sku = "SKU-" + i, Quantity = i, UnitPrice = i * 1.5m } },
                    Total = i * 1.5m * i,
                    LeadTime = TimeSpan.FromHours(i),
                    CreatedUtc = new DateTime(2026, 1, 1).AddDays(i),
                };
            }
            return orders;
        }

        public void ValidateOrder(Order order)
        {
            var problems = new System.Collections.Generic.List<string>();
            if (order == null || order.Lines == null || order.Lines.Length == 0)
                problems.Add("order has no lines");
            if (order != null && order.ShipTo == null)
                problems.Add("no shipping address");

            if (problems.Count > 0)
                throw new FaultException<ValidationFault>(
                    new ValidationFault { Code = "INVALID", Problems = problems.ToArray() },
                    new FaultReason("order failed validation"));
        }

        public PlaceOrderResponse PlaceOrder(PlaceOrderRequest request)
        {
            string company = request.Context == null ? "(no header)" : request.Context.Company;
            string language = request.Context == null ? "-" : request.Context.Language;

            return new PlaceOrderResponse
            {
                Confirmation = string.Format(
                    "{0} x{1} for {2}/{3}", request.ItemId, request.Quantity, company, language)
            };
        }
    }

    public static class Program
    {
        public static int Main(string[] args)
        {
            int port = args.Length > 0 ? int.Parse(args[0]) : 8899;
            SecurityMode mode = args.Length > 1 && args[1] == "Transport"
                ? SecurityMode.Transport
                : SecurityMode.None;

            Uri baseAddress = new Uri("net.tcp://localhost:" + port + "/Demo");

            var binding = new NetTcpBinding(mode);
            // Keep the wire as close to stock as possible; only raise the quotas
            // so EchoLarge can exercise Chars16/Chars32 records.
            binding.MaxReceivedMessageSize = 4 * 1024 * 1024;
            binding.ReaderQuotas.MaxStringContentLength = 4 * 1024 * 1024;
            binding.ReaderQuotas.MaxArrayLength = 4 * 1024 * 1024;

            using (var host = new ServiceHost(typeof(DemoService), baseAddress))
            {
                host.AddServiceEndpoint(typeof(IDemoService), binding, "");

                // Metadata over TCP rather than HTTP: no URL reservation, so the
                // rig runs without administrator rights. Feeds the WSDL codegen.
                host.Description.Behaviors.Add(new ServiceMetadataBehavior());
                host.AddServiceEndpoint(
                    typeof(IMetadataExchange),
                    MetadataExchangeBindings.CreateMexTcpBinding(),
                    "mex");

                try
                {
                    host.Open();
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine("FAILED " + ex.Message);
                    return 1;
                }

                Console.WriteLine("READY " + baseAddress + " security=" + mode);
                Console.Out.Flush();

                // Runs until the harness kills the process.
                System.Threading.Thread.Sleep(System.Threading.Timeout.Infinite);
            }

            return 0;
        }
    }
}
