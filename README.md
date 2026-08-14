# AISI.AcumaticaWebhookAuthenticator

[![CI](https://github.com/AISI-Dev-Co/AISI.AcumaticaWebhookAuthenticator/actions/workflows/ci.yml/badge.svg)](https://github.com/AISI-Dev-Co/AISI.AcumaticaWebhookAuthenticator/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Webhook signature verification for Acumatica ERP.

`PX.Api.Webhooks.IWebhookHandler` hands you a request and leaves authentication entirely to you.
The official sample compares a bearer token with `!=`. This library does the part everyone
re-implements badly: HMAC verification over the raw request bytes, with the header names,
encodings, prefixes and signed-payload conventions that real senders use.

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

The base class reads the body once into a bounded buffer, verifies against it, answers every
failure with the same generic 401 (the diagnostic code goes to `PXTrace` only), and hands the
verified buffer — never the spent stream — to your code. The secret comes from the ERP database,
keyed by the webhook registration and maintained on its own screen.

## Install

Tagged releases (`v*`) build two artifacts via the Release workflow: the
`AISI.AcumaticaWebhookAuthenticator.Core` NuGet package, and the importable customization package
`AISI.WebhookAuthenticator.zip` (screen, table schema, site map, access rights, both assemblies) —
assembled from [customization/AISI.WebhookAuthenticator](customization/AISI.WebhookAuthenticator),
never committed as a zip.

Not yet published to nuget.org. Build from source:

```sh
git clone https://github.com/AISI-Dev-Co/AISI.AcumaticaWebhookAuthenticator
cd AISI.AcumaticaWebhookAuthenticator
dotnet build -c Release -p:AcumaticaBinPath="C:\AcumaticaSites\MySite\Bin"
```

`AcumaticaBinPath` (or the `ACUMATICA_BIN` environment variable) points the Acumatica adapter at a
local 2025 R2+ site's `Bin` for its licensed `PX.*` references; they are never copied to the
output or into any package. To build just the platform-agnostic core, no site is needed:

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
| `JWT` | not built yet | |

`SECRET` and `BASIC` credentials are not bound to the request: anyone who observes one can replay
it against any payload. They exist for senders that offer nothing better; prefer HMAC whenever the
sender supports it. For `BASIC` the stored secret is the whole `user:password` string, and the
adapter sends the RFC 7235 `WWW-Authenticate` challenge on the 401.

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

`{path}` has no source under Acumatica — `PX.Api.Webhooks.WebhookRequest` exposes no request path —
so it resolves only if you construct the context yourself with a path obtained elsewhere. A sender
that signs the request path is not supportable from the platform's request object alone, and
`AuthenticatedWebhookHandlerBase` rejects a `{path}` template up front rather than letting every
request fail as a puzzling 401.

`SignatureExtraction.KeyValueElement("v1")` pulls the signature out of a compound header such as
Stripe's `t=1614556800,v1=5257a8…,v0=6ffbb5…`, and tries every matching element — Stripe emits one
`v1` per active endpoint secret.

Misconfigurations are rejected when the authenticator is constructed, not on the first request.
Configuring a replay window without a `{timestamp}` in the template throws, because a signature
that doesn't cover the timestamp makes validating it pointless. Undefined enum values are rejected
the same way.

### Lifetime

`HmacAuthOptions` is a mutable builder and is not thread-safe. `HmacAuthenticator` copies what it
needs at construction and never reads the options again, so:

- assignments after construction are silently ignored — build a new authenticator instead;
- one options instance shared across several authenticators freezes each at what it read;
- mutating on one thread while constructing on another can be observed part-way through, and a
  half-swapped `Template`/`Timestamp` pair will pass the coherence check because each half is
  individually valid.

Build options at startup, construct the authenticator, discard the options. The authenticator is
immutable and safe to share.

`WebhookAuthContext` retains the body array by reference rather than copying it — a copy per
request would double the memory traffic of every payload, and unlike a secret the body isn't
confidential. Don't mutate it after handing it over: changing it between verification and
deserialisation means processing a payload no signature covered.

## IP allowlist

An administrator configures the allowlist on the webhook secrets screen, next to the secret:
**Allowed IP Addresses** (comma-separated addresses and CIDR blocks, IPv4 and IPv6 — e.g.
`203.0.113.0/24, 2001:db8::/32`), **Client Address Header**, and **Trusted Proxy Depth**. The
entries are validated on save with the same parser the request path uses, changes take effect on
the 30-second cache cadence without a restart, and a stored allowlist that cannot be parsed
(edited past the screen) denies everything rather than restricting nothing.
`AuthenticatedWebhookHandlerBase` applies it automatically around whatever authenticator the
handler creates; a blank field means no IP restriction.

The same gate is available in code for hosts that want it fixed at compile time:

```csharp
new IpAllowlistAuthenticator(
    new HmacAuthenticator(WebhookAuthPresets.GitHub(secrets)),
    IpAllowlist.Parse("203.0.113.0/24", "2001:db8::/32"));
```

**Read the caveat before deploying it.** Acumatica's `WebhookRequest` exposes no remote address,
so the caller's IP can only come from a forwarded header (`X-Forwarded-For` by default) — a header
any sender can write. The gate is only meaningful behind a trusted front proxy that overwrites or
appends to that header on every request. The client address is read counting `trustedProxyDepth`
entries from the *right* of the header (default 1 — one trusted proxy); everything left of that is
the sender's to invent and is ignored. Missing header, unparseable entry, or fewer entries than
the depth all fail closed, with the same uniform 401 as every other failure.

This is defence in depth on top of a signature scheme, or a last resort for a sender that signs
nothing. It is a restriction, not authentication — the inner authenticator still runs for allowed
callers.

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

`ErpSecretProvider` (in the Acumatica adapter) is the production implementation: it reads the
`AISIWebhookSecret` row for the webhook registration the request arrived on. The secret fields are
`[PXRSACryptString]` — Acumatica's own pattern for third-party integration credentials: encrypted
at rest, editable without a redeployment, working on SaaS where there is no file system or
environment to read from. An administrator maintains them on the webhook secrets screen
(`AISIWebhookSecretMaint`, screen `AS301000`); reads are cached for 30 seconds, so an edit takes
effect without an application restart. The table's schema is [sql/AISIWebhookSecret.sql](sql/AISIWebhookSecret.sql).

`AuthenticatedWebhookHandlerBase` wires this up by default — one secret per webhook registration,
including when one handler type is registered under several webhooks. Override
`CreateSecretProvider` to source secrets elsewhere.

The screen is Modern UI only — no ASPX. Its sources are in
[screens/AS/AS301000](screens/AS/AS301000). Delivery is a **customization project** (the flow
verified end to end on a 2026 R1 instance):

1. Copy the two files to the site's `FrontendSources\screen\src\development\screens\AS\AS301000\`
   — the staging tree the Customization Project Editor reads. (The command-line screen build does
   **not** compile this tree; it exists for the editor.)
2. In the Customization Project Editor add: the two DLLs under **Files**; the two screen files
   under **Modern UI Files**; the `AISIWebhookSecret` table under **Database Scripts → Add Custom
   Table Schema**; the site map node (URL `~/Scripts/Screens/{Tenant}/AS301000.html`) under
   **Site Map**; and the screen's role grants under **Access Rights** — without a rights entry the
   sitemap hides the screen from search and `?ScreenId=` navigation entirely.
3. Publish. The publish itself creates the table, registers everything, and runs the frontend
   build (`webpack --env production --env tenant={Tenant}`), compiling the screen into
   `Scripts\Screens\{Tenant}\`.

**Encryption at rest requires a site certificate.** On an instance with no encryption certificate
configured, `[PXRSACryptString]` degrades to base64 obfuscation — the stored value decodes
straight back to the secret. Configure an encryption certificate (Certificates, SM200530) on any
instance whose database backups matter.

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

The core targets `netstandard2.0`, so one assembly serves the net48 runtime Acumatica 2025 R2 uses
and .NET 8+ after Acumatica's migration — no re-target, no fork. The Acumatica adapter targets
`net48` and compiles warning-clean against both ends of the support matrix (25.201 and 26.100).

`CryptographicOperations.FixedTimeEquals` is .NET Standard 2.1 and net48 is 2.0, so
`FixedTimeComparer` supplies it.

| | |
| --- | --- |
| Acumatica | 2025 R2, 2026 R1 |
| Interface | `PX.Api.Webhooks.IWebhookHandler` |

## Design notes

**The signed payload is bytes.** `SignedPayloadTemplate` resolves to `byte[]` and splices the raw
body in verbatim. Composing it as a string would round-trip the body through a decode/encode that
is lossy for a BOM, a non-UTF-8 charset, or an invalid byte sequence. `WebhookRequest.Body` is a
`Stream`, so the exact signed bytes are available — `CreateTextReader()` is not the only way in.

**Failures are indistinguishable.** One 401, one generic body. `AuthFailureCode` goes to the trace,
never to the sender — a caller who can tell "malformed" from "wrong" has an oracle.

**Fail closed.** No secret configured denies the request. It never degrades to unauthenticated
handling.

## Status

Core is complete and tested; the whole `PX.Api.Webhooks.Abstractions` surface is verified against
the decompiled assemblies at both ends of the support matrix — see
[docs/framework-notes.md](docs/framework-notes.md).

- [x] HMAC / HMAC+timestamp, templates, rotation, presets
- [x] `IWebhookHandler` base class (`AuthenticatedWebhookHandlerBase`)
- [x] DAC-backed secret provider and maintenance graph
- [x] Shared-secret, Basic, None schemes
- [x] IP allowlist with CIDR (`IpAllowlistAuthenticator` — requires a trusted front proxy, see
      above)
- [ ] JWT scheme (the real risk is `Microsoft.IdentityModel.*` binding redirects against a site's
      `Bin`, not the token logic)
- [x] On-instance verification: 14-request live matrix against a 2026 R1 site (GitHub's published
      HMAC vector, forged/missing signatures, body cap, ERP-configured allowlist, rotation
      overlap and expiry, BASIC challenge) — handlers in
      [tests/AISI.AcumaticaWebhookAuthenticator.SiteSmokeTest](tests/AISI.AcumaticaWebhookAuthenticator.SiteSmokeTest)
- [ ] NuGet release

## Contributing

```sh
dotnet test tests/AISI.AcumaticaWebhookAuthenticator.Core.Tests
```

No Acumatica instance required for the tests — the core deliberately references nothing from
Acumatica or ASP.NET, and everything testable lives there; the adapter is a thin binding. CI
builds and tests the core only, for the same reason.

New signature schemes need a known-good and a known-bad vector in `SenderVectorTests`. Prefer a
vector published by the sender over one this library computed for itself; the GitHub pair is taken
from GitHub's own documentation for exactly that reason.

Timing safety is asserted structurally rather than by measurement. Wall-clock timing tests flake in
CI and get deleted.

## License

MIT. See [LICENSE](LICENSE).
