# AISI.AcumaticaWebhookAuthenticator

[![CI](https://github.com/AISI-Dev-Co/AISI.AcumaticaWebhookAuthenticator/actions/workflows/ci.yml/badge.svg)](https://github.com/AISI-Dev-Co/AISI.AcumaticaWebhookAuthenticator/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/AISI-Dev-Co/AISI.AcumaticaWebhookAuthenticator?include_prereleases)](https://github.com/AISI-Dev-Co/AISI.AcumaticaWebhookAuthenticator/releases)
[![Acumatica](https://img.shields.io/badge/Acumatica-2025%20R2%20%E2%80%93%202026%20R1-5b3f8f)](docs/framework-notes.md)
[![Targets](https://img.shields.io/badge/targets-netstandard2.0%20%7C%20net48-512bd4)](#compatibility)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Webhook authentication for Acumatica ERP.** `PX.Api.Webhooks.IWebhookHandler` hands you a
request and leaves authentication entirely to you — this library does the part everyone
re-implements badly: HMAC verification over the raw request bytes, with the header names,
encodings, prefixes and signed-payload conventions real senders use, plus admin-managed secrets
in the ERP database.

```csharp
public class PushEventHandler : AuthenticatedWebhookHandlerBase
{
    protected override IWebhookAuthenticator CreateAuthenticator(IWebhookSecretProvider secrets) =>
        new HmacAuthenticator(WebhookAuthPresets.GitHub(secrets));

    protected override Task ProcessAsync(AuthenticatedWebhookContext context, CancellationToken cancellation)
    {
        // context.Body is the exact byte buffer the signature verified.
    }
}
```

That's a complete, authenticated GitHub webhook. The base class reads the body once into a
bounded buffer, verifies against it, answers every failure with the same generic 401, and hands
the verified buffer — never the spent stream — to your code. The secret lives in the ERP
database, maintained by an administrator on its own screen.

## Features

- **Six schemes** — HMAC, HMAC with replay window, shared secret, HTTP Basic, explicit none;
  presets for GitHub, Shopify and Stripe, and a template language for everything else
- **Secrets managed in the ERP** — encrypted `[PXRSACryptString]` storage, a Modern UI
  maintenance screen (AS301000), per-webhook secrets, edits live within 30 seconds, no restart
- **Zero-downtime secret rotation** — old and new secrets accepted until the overlap you set
  expires
- **Per-webhook IP allowlists** — IPv4/IPv6 CIDR, admin-configurable, for deployments behind a
  trusted proxy
- **Security first** — constant-time comparison, fail-closed on missing secrets,
  indistinguishable 401s (diagnostics go to `PXTrace` only), verified-bytes-only processing
- **A signature debugger** — `WebhookSignatureTester` shows what was signed, what was expected
  and what arrived, ending the guess-why-it-401s hour every integration starts with

## Getting started

Grab both artifacts from the [latest release](https://github.com/AISI-Dev-Co/AISI.AcumaticaWebhookAuthenticator/releases):
`AISI.WebhookAuthenticator.zip` (the customization package) and the
`AISI.AcumaticaWebhookAuthenticator.Core` NuGet package.

1. **Import and publish** `AISI.WebhookAuthenticator.zip` on the Customization Projects screen
   (SM204505). Publishing creates the secrets table, registers the Webhook Secrets screen and its
   access rights, and compiles the Modern UI — no manual SQL, no frontend build.
2. **Write a handler** like the one above in your own customization or extension library,
   referencing the two shipped assemblies (or the NuGet package for the core types).
3. **Register the webhook** on the Webhooks screen (SM304000) with your handler's type name —
   Acumatica gives you the endpoint URL.
4. **Enter the secret** on the Webhook Secrets screen (AS301000) for that webhook. Done — requests
   that don't verify never reach your code.

> **Note:** if your tenant's login name differs from the packaged one, adjust the Webhook Secrets
> site map URL after the first publish — see the
> [package notes](customization/AISI.WebhookAuthenticator/README.md).

### Building from source

```sh
git clone https://github.com/AISI-Dev-Co/AISI.AcumaticaWebhookAuthenticator
cd AISI.AcumaticaWebhookAuthenticator
dotnet build -c Release -p:AcumaticaBinPath="C:\\AcumaticaSites\\MySite\\Bin"
```

`AcumaticaBinPath` (or the `ACUMATICA_BIN` environment variable) points the Acumatica adapter at
a local 2025 R2+ site's `Bin` for its licensed `PX.*` references — they are never copied into any
output or package. The platform-agnostic core needs no site at all:

```sh
dotnet build src/AISI.AcumaticaWebhookAuthenticator.Core -c Release
```

## Schemes

| Code | Type | What authenticates |
| --- | --- | --- |
| `HMAC` | `HmacAuthenticator` | HMAC signature over a templated payload |
| `HMACTS` | `HmacAuthenticator` with `Timestamp` | the same, inside a replay window |
| `SECRET` | `SharedSecretAuthenticator` | the shared secret itself in a header |
| `BASIC` | `BasicAuthenticator` | RFC 7617 `Authorization: Basic` |
| `NONE` | `NoneAuthenticator.Instance` | nothing — an explicit, recorded decision |
| `JWT` | *planned* | |

`SECRET` and `BASIC` credentials are not bound to the request: anyone who observes one can replay
it against any payload. They exist for senders that offer nothing better — prefer HMAC whenever
the sender supports it. For `BASIC` the stored secret is the whole `user:password` string, and
the 401 carries the RFC 7235 `WWW-Authenticate` challenge.

### Presets

| Preset | Header | Encoding | Signs |
| --- | --- | --- | --- |
| `WebhookAuthPresets.GitHub` | `X-Hub-Signature-256` | hex, `sha256=` prefix | body |
| `WebhookAuthPresets.Shopify` | `X-Shopify-Hmac-Sha256` | base64 | body |
| `WebhookAuthPresets.Stripe` | `Stripe-Signature` | hex, `t=`/`v1=` list | `{timestamp}.{body}` |

### Custom senders

Everything else is expressible with `HmacAuthOptions`:

```csharp
var options = new HmacAuthOptions(secretProvider, signatureHeader: "X-Signature")
{
    Algorithm = HmacAlgorithm.Sha256,             // Sha1, Sha256, Sha512
    Encoding = SignatureEncoding.Base64,          // Hex, Base64
    SignaturePrefix = "v1=",
    Extraction = SignatureExtraction.Whole,       // or KeyValueElement("v1") for compound headers
    Template = SignedPayloadTemplate.Parse("{method}\\n{timestamp}\\n{body}"),
    Timestamp = TimestampValidation.FromHeader("X-Timestamp", TimeSpan.FromMinutes(5)),
};
```

Template tokens: `{body}`, `{timestamp}`, `{method}`, `{path}`, `{header:Name}`; literal braces
are `{{` and `}}`. `SignatureExtraction.KeyValueElement("v1")` pulls signatures out of compound
headers like Stripe's `t=1614556800,v1=5257a8…` and tries every matching element.

Misconfigurations throw when the authenticator is constructed, not as puzzling 401s in
production: a replay window over a timestamp the template doesn't sign, an undefined enum value,
or — under Acumatica, which exposes no request path — a `{path}` template.

Build options at startup, construct the authenticator, discard the options: `HmacAuthOptions` is
a mutable builder that the authenticator snapshots at construction and never reads again. The
authenticator itself is immutable and safe to share.

## Secret storage and rotation

Secrets live in the `AISIWebhookSecret` table ([schema](sql/AISIWebhookSecret.sql)), one row per
webhook registration, encrypted with `[PXRSACryptString]` — Acumatica's own pattern for
integration credentials, and the only one that works on SaaS. `AuthenticatedWebhookHandlerBase`
wires this up automatically; override `CreateSecretProvider` to source secrets elsewhere, or use
`StaticSecretProvider` in tests (never in production).

Rotation is first-class — a sender mid-rotation signs with either secret until the overlap
closes:

```csharp
WebhookSecret secret = WebhookSecret
    .FromUtf8(current)
    .WithRotatingUtf8(previous, expiresOn: DateTimeOffset.UtcNow.AddDays(7));
```

On the screen that's just the Rotating Secret and Rotation Ends (UTC) columns. Key material never
leaves `WebhookSecret`; verification happens inside it.

> **Encryption at rest requires a site certificate.** Without one, `[PXRSACryptString]` degrades
> to base64 obfuscation. Configure an encryption certificate (SM200530) on any instance whose
> database backups matter.

## IP allowlists

Set **Allowed IP Addresses** (`203.0.113.0/24, 2001:db8::/32`), **Client Address Header** and
**Trusted Proxy Depth** on the Webhook Secrets screen — validated on save, applied automatically,
live within 30 seconds. An unparseable stored list denies everything rather than restricting
nothing. The same gate is available in code:

```csharp
new IpAllowlistAuthenticator(
    new HmacAuthenticator(WebhookAuthPresets.GitHub(secrets)),
    IpAllowlist.Parse("203.0.113.0/24", "2001:db8::/32"));
```

> **Read before deploying:** Acumatica exposes no remote address, so the caller's IP comes from a
> forwarded header — which any sender can write. The gate is only meaningful behind a trusted
> front proxy that controls that header. The client address is read `trustedProxyDepth` entries
> from the *right*; everything left of that is the sender's to invent and is ignored. This is
> defence in depth on top of a signature scheme, not authentication.

## Debugging a mismatch

```csharp
SignatureTestReport report = WebhookSignatureTester.Test(options, capturedRequest);

report.SignedPayloadPreview;   // "1614556800.{\"id\":\"evt_1\"}"
report.ExpectedSignatures;     // current secret first, then rotating if the overlap is live
report.ProvidedSignatures;     // what the sender sent
report.FailureCode;            // e.g. "signature_prefix_mismatch"
```

The report contains expected signatures — never return it in an HTTP response.

## Compatibility

| | |
| --- | --- |
| Acumatica | 2025 R2 – 2026 R1 (`PX.Api.Webhooks.IWebhookHandler`) |
| Core | `netstandard2.0` — no Acumatica or ASP.NET references |
| Adapter | `net48`, compiled against both ends of the support matrix |

The core serves today's net48 runtime and .NET 8+ after Acumatica's migration without a re-target.
Every platform behavior the adapter relies on is verified against the decompiled assemblies at
both supported versions — the receipts are in [docs/framework-notes.md](docs/framework-notes.md).

## Security model

- **The signed payload is bytes.** Templates resolve to `byte[]` with the raw body spliced in
  verbatim — never round-tripped through a string, which is lossy for BOMs, charsets and invalid
  sequences.
- **Failures are indistinguishable.** One 401, one generic body; `AuthFailureCode` goes to the
  trace, never to the sender — a caller who can tell "malformed" from "wrong" has an oracle.
- **Fail closed.** No secret, unparseable allowlist, over-limit body: denied. Nothing ever
  degrades to unauthenticated handling.
- **Constant time.** Every secret comparison goes through a fixed-time comparer, never
  short-circuited across rotation candidates.

## Roadmap

- JWT scheme (the real work is `Microsoft.IdentityModel.*` binding redirects against a site's
  `Bin`, not the token logic)
- Retries — redelivery handling for payloads whose processing failed after authenticating
- Full payload capture to Acumatica's webhook request record, so the platform's built-in request
  log carries the complete verified body
- nuget.org publication on version tags — add a `NUGET_API_KEY` Actions secret to enable the
  push (the nupkg is already a Release asset)

> Need this published on a SaaS tenant, wired to a live sender, or extended past this scope?
> [AISI Dev Co](https://github.com/AISI-Dev-Co) does scoped Acumatica customisation for VARs.

## Contributing

```sh
dotnet test tests/AISI.AcumaticaWebhookAuthenticator.Core.Tests
```

No Acumatica instance required — everything testable lives in the core, and CI builds and tests
exactly that. New signature schemes need a known-good and a known-bad vector in
`SenderVectorTests`, preferably published by the sender (the GitHub pair comes from GitHub's own
docs). Timing safety is asserted structurally; wall-clock timing tests flake in CI and get
deleted.

## License

[MIT](LICENSE)
