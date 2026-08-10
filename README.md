# AISI.AcumaticaWebhookAuthenticator

[![CI](https://github.com/AISI-Dev-Co/AISI.AcumaticaWebhookAuthenticator/actions/workflows/ci.yml/badge.svg)](https://github.com/AISI-Dev-Co/AISI.AcumaticaWebhookAuthenticator/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Webhook signature verification for Acumatica ERP.

`PX.Api.Webhooks.IWebhookHandler` hands you a request and leaves authentication entirely to you.
The official sample compares a bearer token with `!=`. This library does the part everyone
re-implements badly: HMAC verification over the raw request bytes, with the header names,
encodings, prefixes and signed-payload conventions that real senders use.

```csharp
var options = WebhookAuthPresets.Stripe(secretProvider);

if (!new HmacAuthenticator(options).Authenticate(context).Succeeded)
{
    response.StatusCode = StatusCodes.Status401Unauthorized;
    return;
}
```

## Install

Not yet published to nuget.org. Build from source:

```sh
git clone https://github.com/AISI-Dev-Co/AISI.AcumaticaWebhookAuthenticator
cd AISI.AcumaticaWebhookAuthenticator
dotnet build -c Release
```

## Presets

Three senders are configured for you. Everything else is expressible with `HmacAuthOptions`.

| Preset | Header | Encoding | Signs |
| --- | --- | --- | --- |
| `WebhookAuthPresets.GitHub` | `X-Hub-Signature-256` | hex, `sha256=` prefix | body |
| `WebhookAuthPresets.Shopify` | `X-Shopify-Hmac-Sha256` | base64 | body |
| `WebhookAuthPresets.Stripe` | `Stripe-Signature` | hex, `t=`/`v1=` list | `{timestamp}.{body}` |

## Configuration

```csharp
var options = new HmacAuthOptions(secretProvider, signatureHeader: "X-Signature")
{
    Algorithm = HmacAlgorithm.Sha256,             // Sha1, Sha256, Sha512
    Encoding = SignatureEncoding.Base64,          // Hex, Base64
    SignaturePrefix = "v1=",
    Extraction = SignatureExtraction.Whole,       // or KeyValueElement("v1")
    Template = SignedPayloadTemplate.Parse("{method}\n{path}\n{timestamp}\n{body}"),
    Timestamp = TimestampValidation.FromHeader("X-Timestamp", TimeSpan.FromMinutes(5)),
};
```

Template tokens: `{body}`, `{timestamp}`, `{method}`, `{path}`, `{header:Name}`. Braces are escaped
`{{` and `}}`.

`SignatureExtraction.KeyValueElement("v1")` pulls the signature out of a compound header such as
Stripe's `t=1614556800,v1=5257a8…,v0=6ffbb5…`, and tries every matching element — Stripe emits one
`v1` per active endpoint secret.

Misconfigurations are rejected when the authenticator is constructed, not on the first request.
Configuring a replay window without a `{timestamp}` in the template throws, because a signature
that doesn't cover the timestamp makes validating it pointless.

## Secret rotation

A sender mid-rotation signs with either secret until the overlap closes.

```csharp
WebhookSecret secret = WebhookSecret
    .FromUtf8(current)
    .WithRotatingUtf8(previous, expiresOn: DateTimeOffset.UtcNow.AddDays(7));
```

Both are accepted until `expiresOn`, then only the current one. Key material never leaves
`WebhookSecret`; verification happens inside it.

## Secret storage

Implement `IWebhookSecretProvider`. The intended production implementation reads a
`[PXRSACryptString]` DAC field — Acumatica's own pattern for third-party integration credentials.
It's encrypted at rest, editable without a redeployment, unaffected by the move off .NET Framework,
and it works on SaaS, where there is no file system or environment to read from.

`StaticSecretProvider` exists for tests. Don't ship a secret compiled into an assembly.

## Debugging a mismatch

`WebhookSignatureTester` reports what your configuration signed and what it produced, against what
arrived:

```csharp
SignatureTestReport report = WebhookSignatureTester.Test(options, capturedRequest);

report.SignedPayloadPreview;   // "1614556800.{\"id\":\"evt_1\"}"
report.ExpectedSignatures;     // current secret first, then rotating if the overlap is live
report.ProvidedSignatures;     // what the sender sent
report.FailureCode;            // e.g. "signature_prefix_mismatch"
```

The report contains expected signatures. Never return it in an HTTP response.

## Compatibility

Targets `netstandard2.0`, so one assembly serves the net48 runtime Acumatica 2025 R2 uses and
.NET 8+ after Acumatica's migration — no re-target, no fork.

`CryptographicOperations.FixedTimeEquals` is .NET Standard 2.1 and net48 is 2.0, so
`FixedTimeComparer` supplies it.

| | |
| --- | --- |
| Acumatica | 2025 R2, 2026 R1 |
| Interface | `PX.Api.Webhooks.IWebhookHandler` |

## Design notes

**The signed payload is bytes.** `SignedPayloadTemplate` resolves to `byte[]` and splices the raw
body in verbatim. Composing it as a string would round-trip the body through a decode/encode that
is lossy for a BOM, a non-UTF-8 charset, or an invalid byte sequence.

**Failures are indistinguishable.** One 401, one generic body. `AuthFailureCode` goes to the trace,
never to the sender — a caller who can tell "malformed" from "wrong" has an oracle.

**Fail closed.** No secret configured denies the request. It never degrades to unauthenticated
handling.

## Status

Core is complete and tested. The Acumatica adapter is blocked on one unknown — whether
`WebhookContext.Request` exposes raw bytes or only `CreateTextReader()`. See
[docs/framework-notes.md](docs/framework-notes.md).

- [x] HMAC / HMAC+timestamp, templates, rotation, presets
- [ ] `IWebhookHandler` base class
- [ ] DAC-backed secret provider and maintenance screen
- [ ] Shared-secret, Basic, JWT schemes
- [ ] IP allowlist with CIDR
- [ ] NuGet release

## Contributing

```sh
dotnet test
```

75 tests, no Acumatica instance required — the core deliberately references nothing from Acumatica
or ASP.NET.

New signature schemes need a known-good and a known-bad vector in `SenderVectorTests`. Prefer a
vector published by the sender over one this library computed for itself; the GitHub pair is taken
from GitHub's own documentation for exactly that reason.

Timing safety is asserted structurally rather than by measurement. Wall-clock timing tests flake in
CI and get deleted.

## License

MIT. See [LICENSE](LICENSE).
