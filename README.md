# pynettcp

A native Python client for WCF `net.tcp://` services. No CLR, no `pythonnet`, no generated C# proxy DLL.

## Why

There is no Python library that can call a WCF `NetTcpBinding` service. `zeep` speaks SOAP over HTTP only. So the usual workaround is to route through .NET:

```
Python  ->  pythonnet  ->  CLR  ->  proxy.dll (svcutil)  ->  WCF  ->  net.tcp://host:port
```

That drags in .NET Framework and Visual Studio on every machine, needs the proxy DLL rebuilt and redeployed whenever the service contract changes, and inherits CLR-hosting quirks — most notoriously that .NET reads the *host process* config, so `python.exe.config` is consulted and the DLL's own `.config` is silently ignored.

`net.tcp` is not proprietary. It is four published Microsoft Open Specifications stacked on a plain TCP socket:

```
Python  ->  socket  ->  net.tcp://host:port
```

| Layer | Specification | Module |
|---|---|---|
| Framing | [MC-NMF], [MC-NMFTB] | `framing.py` |
| Security | [MS-NNS] | `nns.py`, `security.py` |
| Encoding | [MC-NBFX], [MC-NBFS] | `nbfx.py`, `nbfs.py`, `dictionary.py` |
| Messaging | SOAP 1.2 + WS-Addressing | `soap.py`, `channel.py`, `faults.py` |

## Status

| Milestone | State |
|---|---|
| M0 — oracle harness, static dictionary | done |
| M1 — `varint`, `nbfx` encoder/decoder | done, byte-exact vs .NET |
| M2 — `nbfs` session dictionary, `soap` envelope | done, byte-exact vs WCF |
| M3 — `framing` (MC-NMF), `channel`, demo service | done, **live calls work** |
| M4 — `nns`, `security` (NegotiateStream) | done, **authenticated calls work** |
| M5 — WSDL → Python codegen | done, **generated clients work** |

All five milestones are complete: `pynettcp` reads a service's WSDL, generates a
typed client, and calls it over `net.tcp` — unsecured or with Windows
authentication, encrypted and signed over Kerberos/NTLM.

## Usage

Generate a client from the service's metadata — this is the `svcutil` replacement:

```
python -m pynettcp.codegen net.tcp://host:8899/Demo/mex -o demo_client.py
python -m pynettcp.codegen http://host:8101/Svc?wsdl   -o svc_client.py
```

Then call it:

```python
from demo_client import DemoServiceClient, LeaveRequest, DemoContext, ServiceFault

with DemoServiceClient(security="transport", spn="host/server.corp.com") as client:
    client.echo("hello")                      # -> 'hello'
    client.add(20, 22)                        # -> 42
    client.create_leave(LeaveRequest(EmployeeId="E42", TotalDays=3))
    # -> LeaveResult(Reference='LV-E42-3', Accepted=True)

    # SOAP headers become keyword-only arguments
    client.place_order("WIDGET-1", 5, context=DemoContext(Company="ACME"))
```

SOAP headers matter more than they look. They are declared in `wsdl:binding`
rather than in the portType, so they never appear among an operation's
parameters — and a service that requires one rejects every call without it.
Dynamics AX's `CallContext` is the standard example.

`examples/generated/demo_client.py` is real generator output, checked in so the
shape is visible without running anything.

The low-level API is still there when a service has no usable metadata:

```python
from pynettcp import Channel, SessionStr

with Channel("net.tcp://host:8899/Demo") as channel:
    reply = channel.call(action="urn:DemoService/IDemoService/Echo", body=...)
```

Verified end to end against the demo service, in both security modes: metadata
fetched over `net.tcp` MEX, generated clients calling every operation, complex
types round-tripping as dataclasses, 300 KB payloads spanning many TCP segments
(and, when secured, many encrypted frames), SOAP faults raised as typed
exceptions, and framing faults (`EndpointNotFound`) for a bad endpoint path.

### Scope

Supported: document/literal operations, SOAP headers, `xs:sequence` complex
types, nested types, arrays of scalars and of complex types, enums, `Guid`,
`decimal`, `TimeSpan`, nullable value types, anonymous inline types (WCF
dictionaries), `simpleType` aliases, types spanning namespaces, typed faults,
and both security modes.

Not supported: `xs:choice`, `xs:any`, inheritance via `complexContent`, and
`xsi:type` polymorphism — these raise `UnsupportedSchema` naming the construct,
rather than generating a client that fails later against the server.

Typed faults come back as the fault's own contract type:

```python
try:
    client.validate_order(order)
except ServiceFault as e:
    e.reason            # 'order failed validation'
    e.code              # 's:Sender'
    e.detail.Problems   # ['order has no lines', 'no shipping address']
```

**pynettcp reproduces a real three-message WCF session byte-for-byte:**

```
msg E1: ours= 216B wcf= 216B  identical=True
msg E2: ours= 114B wcf= 114B  identical=True
msg E3: ours= 114B wcf= 114B  identical=True
```

That single test exercises the session-block framing, dictionary id
allocation, namespace placement and text-record selection all at once.

## Design note: the preamble must not share a read with the first token

The single hardest bug in the project, recorded here because it costs days.

A secured connection ends its preamble with `UpgradeRequest`, then exchanges
SPNEGO tokens. WCF's client pipelines those — it sends the first token without
waiting for the `UpgradeResponse` — so it is tempting to do the same.

Don't. WCF's `ServerSessionPreambleConnectionReader` decodes the preamble out of
whatever a single socket read returned, and after the upgrade it resumes
decoding **from that same buffer**. If the first token shares a read with the
preamble, those bytes are still sitting there and get decoded as the record that
should have followed. The server lands on byte 2 of `16 01 00 00 7b` and reports:

```
Expected record type 'PreambleEnd', found 'Version'
```

having already logged *"The stream security upgrade was accepted successfully"*.
So it presents as a crypto failure, and on the wire it is just a connection
reset with no diagnostic. `pynettcp` waits for the `UpgradeResponse`, which
turns the boundary from a race into a fact for one round trip per connection.

Finding this needed `tests/rig/NmfEcho.cs` — a transparent MC-NMF server that
performs the same upgrade and prints every byte it decrypts. It proved the
NegotiateStream layer was correct while WCF was still rejecting us, which is
what narrowed the search to buffering.

## Testing policy

Tests never touch a production service. Byte fixtures come from a throwaway
`DataContract` compiled on the fly (`tools/gen_session_fixtures.py`), and the
live tests run against a purpose-built demo WCF service in `tests/rig` that the
suite compiles on demand, starts on a random free port and tears down
afterwards — never against anyone's real ERP endpoint.

## How correctness is established

Every claim about the wire format is checked against **WCF's own encoder**, not against a reading of the specification. `tools/oracle.py` drives .NET's `XmlDictionaryWriter` in-process through `pythonnet`, and the test suite asserts our bytes are identical:

```
$ python -m pytest -q
202 passed
```

`pythonnet` is a *development* dependency for this purpose only. The shipped library never loads the CLR.

The static string table is generated the same way rather than transcribed — `python tools/gen_dictionary.py` reflects 487 entries straight out of `System.ServiceModel.ServiceModelDictionary.Version1`, so a typo cannot silently corrupt every message.

### Known deliberate divergence

Past roughly 169 UTF-8 bytes, .NET stops folding `EndElement` into the text record, because the string no longer fits the 512-byte buffer it would have to rewrite. That is an artefact of its internal buffering, not a protocol rule: `98 <len> <bytes> 01` and `99 <len> <bytes>` are both valid NBFX and decode identically. We always fold, and the tests assert semantic rather than byte equality for long text.

## Design note: dictionary compression is opt-in, and static ≠ session

NBFX compresses strings via a shared dictionary, but *only where the caller asks for it*. .NET expresses this through overloads — `WriteStartElement(string, ...)` writes a literal record, `WriteStartElement(XmlDictionaryString, ...)` writes a dictionary record — and a plain string whose text happens to appear in the table is **not** compressed.

There is a second, subtler rule. Whether a string goes to the *static* table or the *session* table is decided by **which dictionary it came from**, not by looking its text up. WCF proves it: `http://www.w3.org/2001/XMLSchema-instance` sits at static index 441, yet a DataContract body still interns it into the session, because the serializer's strings belong to its own dictionary.

`pynettcp` models both rules with two marker types — `DictStr` for envelope infrastructure, `SessionStr` for anything from the data contract:

```python
from pynettcp import BinaryXmlWriter, DictStr

SOAP12 = DictStr("http://www.w3.org/2003/05/soap-envelope")

w = BinaryXmlWriter()
w.start_element("s", DictStr("Envelope"), SOAP12)
w.start_element("s", DictStr("Body"), SOAP12)
w.end_element()
w.end_element()
w.getvalue()   # -> 56 02 0b 01 73 04 56 0e 01 01
```

## Design note: session mode has a hidden prefix

Under `NetTcpBinding` the payload of a `SizedEnvelope` is **not** a bare NBFX document. It is preceded by the strings that message adds to the dictionary both peers build up over the connection:

```
<varint: byte length of block>
<varint len><UTF-8 bytes>  ... repeated
<NBFX document>
```

Message 1 of the fixture opens with a 103-byte block naming six strings; messages 2 and 3 open with `00` and refer to them by id. Skipping that prefix makes the server read a string length as a record type and drop the connection. Read and write dictionaries are numbered **independently** — `SessionCodec` keeps one for each direction.

## Development

```
pip install -e ".[dev]"
python -m pytest -q
python tools/gen_dictionary.py     # regenerate the static table (needs .NET)
```

## License

MIT.
