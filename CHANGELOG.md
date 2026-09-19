# Changelog

All notable changes to this project are documented here.
This project follows [Semantic Versioning](https://semver.org/).

## [0.1.0] - unreleased

First public release.

### Added
- `[MC-NMF]` .NET Message Framing over a plain TCP socket.
- `[MS-NNS]` NegotiateStream transport security via `pyspnego` (Kerberos/NTLM).
- `[MC-NBFX]` / `[MC-NBFS]` binary XML encoding with static and per-session
  dictionaries, byte-identical to WCF for the verified fixtures.
- SOAP 1.2 + WS-Addressing 1.0 envelopes, typed SOAP fault parsing.
- `Channel`, the low-level duplex-session client.
- WSDL/MEX code generation (`pynettcp-gen`, `python -m pynettcp.codegen`).
- `PyNetTcpError`, a single base class for every error the library raises.
- `py.typed` marker, so type hints reach consumers.

### Known limitations
- `SecurityMode.Message`, reliable sessions, transactions, streaming,
  duplex callbacks, MTOM and SOAP 1.1 are not implemented.
- `xs:choice`, `xs:any`, `complexContent` inheritance and `xsi:type`
  polymorphism raise `UnsupportedSchema` at generation time.
- A `Channel` serialises concurrent calls; use one channel per thread for
  throughput.
- The session dictionary is not reset at `MaxSessionSize`; a long-lived
  channel that keeps interning new strings will raise `SessionSizeExceeded`.
- A WSDL describing several services (a Dynamics AX *service group*) is
  flattened into a single generated client.
