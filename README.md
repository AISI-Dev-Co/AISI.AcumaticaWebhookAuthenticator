# AISI.AcumaticaWebhookAuthenticator

[![CI](https://github.com/AISI-Dev-Co/AISI.AcumaticaWebhookAuthenticator/actions/workflows/ci.yml/badge.svg)](https://github.com/AISI-Dev-Co/AISI.AcumaticaWebhookAuthenticator/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/AISI-Dev-Co/AISI.AcumaticaWebhookAuthenticator?include_prereleases)](https://github.com/AISI-Dev-Co/AISI.AcumaticaWebhookAuthenticator/releases)
[![Acumatica](https://img.shields.io/badge/Acumatica-2025%20R2%20%E2%80%93%202026%20R1-5b3f8f)](docs/framework-notes.md)
[![Targets](https://img.shields.io/badge/targets-netstandard2.0%20%7C%20net48-512bd4)](#compatibility)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Webhook authentication for Acumatica ERP:** inherit `AuthenticatedWebhookHandlerBase` instead
of implementing `PX.Api.Webhooks.IWebhookHandler`, and every request is verified (HMAC, JWT and
more) against a secret an administrator maintains in the ERP before your code sees it.

```csharp
public class PushEventHandler : AuthenticatedWebhookHandlerBase
{
    protected override IWebhookAuthenticator CreateAuthenticator(IWebhookSecretProvider secrets) =>
        new JwtAuthenticator(WebhookAuthPresets.JwtBearer(secrets));

    protected override Task ProcessAsync(AuthenticatedWebhookContext context, CancellationToken cancellation)
    {
        // context.Body is the request body, bound to the token by its `bh` claim.
        return Task.CompletedTask;
    }
}
```

That's a complete Bearer JWT webhook; HMAC senders use `WebhookAuthPresets.GitHub` / `Shopify` /
`Stripe` instead. The base class reads the body once into a bounded buffer, verifies against it,
answers every failure with the same generic 401, and hands the buffer — never the spent stream —
to your code.

## Features

- **Schemes** — HMAC over the request body, HMAC with replay window, compact JWT (HS256/HS512),
  shared secret, HTTP Basic, explicit none; presets for GitHub, Shopify, Stripe and Bearer JWT,
  plus a template language for other HMAC senders
- **Secrets managed in the ERP** — encrypted `[PXRSACryptString]` storage, a Modern UI
  maintenance screen (AS301000), per-webhook secrets, edits live within 30 seconds, no restart
- **Zero-downtime secret rotation** — old and new secrets accepted until the overlap you set
  expires; **Generate Secret** and **Rotate Secret** on the screen, shown once and never again
- **Secret encodings** — UTF-8 text, base64, hex, or Standard Webhooks (`whsec_`, Svix and
  friends), per webhook
- **Per-webhook IP allowlists** — IPv4/IPv6 CIDR, admin-configurable, for deployments behind a
  trusted proxy
- **A signature debugger** — `WebhookSignatureTester` shows what was signed, what was expected
  and what arrived

## Getting started

1. **Core** — take `AISI.AcumaticaWebhookAuthenticator.Core` from the
   [latest release](https://github.com/AISI-Dev-Co/AISI.AcumaticaWebhookAuthenticator/releases)
   (or build `src/AISI.AcumaticaWebhookAuthenticator.Core`; no site required).
2. **Customization package** — the adapter needs a site's licensed `PX.*` assemblies to compile,
   so `AISI.WebhookAuthenticator.zip` is packed locally against a 2025 R2+ site `Bin`
   ([how](customization/AISI.WebhookAuthenticator/README.md)). Import and publish it on
   SM204505: secrets table, Webhook Secrets screen, adapter.
3. **Write a handler** like the one above, referencing Core and the adapter.
4. **Register the webhook** on SM304000 with your handler's type name.
5. **Enter the secret** on AS301000. Requests that don't verify never reach your code.

### Building from source

```sh
git clone https://github.com/AISI-Dev-Co/AISI.AcumaticaWebhookAuthenticator
cd AISI.AcumaticaWebhookAuthenticator
dotnet build -c Release -p:AcumaticaBinPath="C:\AcumaticaSites\MySite\Bin"
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
| `JWT` | `JwtAuthenticator` | Compact JWS (`HS256` / `HS512`) **over the token**, plus required `bh` body-hash claim |

**Unbound credentials.** `SECRET` and `BASIC` credentials, and a JWT without a body-hash claim,
are not bound to the request: anyone who observes one can replay it against any payload. They
exist for senders that offer nothing better — prefer a body-HMAC scheme (GitHub / Shopify /
Stripe / `HmacAuthenticator`) whenever the sender supports it. JWS HMAC covers the token's
`header.payload` only (RFC 7515), so `JwtBearer` requires claim `bh` (base64url SHA-256 of the raw
body, compared in constant time) by default; leave `RequireBodyHash` on.

For `BASIC` the stored secret is the whole `user:password` string, and the 401 carries the
RFC 7235 `WWW-Authenticate` challenge.

`JwtBearer(secrets)` also requires `aud` to equal the webhook registration id, so a reused secret
cannot be presented to a different webhook; `JwtBearer(secrets, audience)` checks that audience
instead. `exp` is required unless you turn that off; `iss` is checked only when configured. RS256
is not implemented — it would pull `Microsoft.IdentityModel.*` into the site `Bin`.

### Presets

| Preset | Header | Encoding | Signs |
| --- | --- | --- | --- |
| `WebhookAuthPresets.GitHub` | `X-Hub-Signature-256` | hex, `sha256=` prefix | body |
| `WebhookAuthPresets.Shopify` | `X-Shopify-Hmac-Sha256` | base64 | body |
| `WebhookAuthPresets.Stripe` | `Stripe-Signature` | hex, `t=`/`v1=` list | `{timestamp}.{body}` |
| `WebhookAuthPresets.JwtBearer` | `Authorization: Bearer` | JWT compact, HS256 | the token; body via its `bh` claim |

### Custom senders

Everything else is expressible with `HmacAuthOptions`:

```csharp
var options = new HmacAuthOptions(secretProvider, signatureHeader: "X-Signature")
{
    Algorithm = HmacAlgorithm.Sha256,             // Sha1, Sha256, Sha512
    Encoding = SignatureEncoding.Base64,          // Hex, Base64
    SignaturePrefix = "v1=",
    Extraction = SignatureExtraction.Whole,       // or KeyValueElement("v1") for compound headers
    Template = SignedPayloadTemplate.Parse("{method}\n{timestamp}\n{body}"),
    Timestamp = TimestampValidation.FromHeader("X-Timestamp", TimeSpan.FromMinutes(5)),
};
```

Template tokens: `{body}`, `{timestamp}`, `{method}`, `{path}`, `{header:Name}`; literal braces
are `{{` and `}}`. `SignatureExtraction.KeyValueElement("v1")` pulls signatures out of compound
headers like Stripe's `t=1614556800,v1=5257a8…` and tries every matching element.

Misconfigurations throw when the authenticator is constructed, not as puzzling 401s in
production: a replay window over a timestamp the template doesn't sign, or an undefined enum
value. Acumatica exposes no request path, so the adapter rejects a `{path}` template on the
registration's first request.

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

On the screen, **Rotate Secret** does it in one click: the saved secret moves to Rotating Secret,
Rotation Ends (UTC) is set seven days out (edit it if you need longer), and a new random secret
is shown once for you to paste into the sender. **Generate Secret** replaces the secret
immediately, with no overlap — for a first secret, or a leaked one. Key material never leaves
`WebhookSecret`; verification happens inside it.

**Secret Encoding** says how the stored text becomes key bytes, for the current and rotating
secret alike: *Text (UTF-8)* (the default, and what most dashboards mean), *Base64*, *Hex*, or
*Standard Webhooks* (`whsec_` plus base64). In code, `WebhookSecret.Parse(text, encoding)`, and
`SecretGenerator.Generate(encoding)` for a fresh one. Changing the encoding re-checks the saved
secrets; one that no longer decodes is refused on save rather than at request time. Rows saved
before 0.3.0 have no encoding and read as UTF-8, so upgrading changes nothing until you pick one.

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
Every platform behaviour the adapter relies on is verified against the decompiled assemblies at
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

- Retries — redelivery handling for payloads whose processing failed after authenticating
- Full payload capture to Acumatica's webhook request record, so the platform's built-in request
  log carries the complete verified body

> Need this published on a SaaS tenant, wired to a live sender, or extended past this scope?
> [AISI Dev Co](https://github.com/AISI-Dev-Co) does scoped Acumatica customisation for VARs.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
