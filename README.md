# AISI.AcumaticaWebhookAuthenticator

Inbound webhook authentication for Acumatica ERP, so that nobody writes signature verification by
hand again.

Acumatica gives you `PX.Api.Webhooks.IWebhookHandler` and nothing else. The published guidance
demonstrates authentication with a hardcoded token compared using `!=`, which is both unrotatable
and vulnerable to timing analysis. Every implementer then rewrites the same signature verification,
usually slightly wrong, and discovers the difference between hex and base64 an hour into the
integration.

This library supplies the authentication layer: HMAC verification against the raw request bytes,
signed-payload templates that cover the conventions real senders actually use, replay windows,
secret rotation overlap and a constant-time comparison — with presets for GitHub, Shopify and
Stripe.

**Status: in development.** The core is built and tested; the Acumatica adapter is gated on the
open questions in [`docs/framework-notes.md`](docs/framework-notes.md).

## What it looks like

```csharp
var options = WebhookAuthPresets.Stripe(new ErpSecretProvider("SHIPPING"));

AuthResult result = new HmacAuthenticator(options).Authenticate(context);
if (!result.Succeeded)
{
    // one 401, one generic body, every time
}
```

Or spelled out, for a sender nobody has written a preset for:

```csharp
var options = new HmacAuthOptions(secretProvider, signatureHeader: "X-Signature")
{
    Algorithm = HmacAlgorithm.Sha256,
    Encoding = SignatureEncoding.Base64,
    SignaturePrefix = "v1=",
    Template = SignedPayloadTemplate.Parse("{method}\n{path}\n{timestamp}\n{body}"),
    Timestamp = TimestampValidation.FromHeader("X-Timestamp", TimeSpan.FromMinutes(5)),
};
```

## Design notes

**The body is bytes, not a string.** `SignedPayloadTemplate` resolves to `byte[]` and splices the
raw body in verbatim; only literal segments and scalar tokens are UTF-8 encoded. Building the
signed payload as a string would force the body through a decode/encode round trip that is lossy
for a BOM, a non-UTF-8 charset or an invalid byte sequence — and would break every HMAC scheme in
existence for exactly the senders hardest to debug.

**Templates, not vendor classes.** GitHub signs the body; Stripe signs `{timestamp}.{body}`; others
prepend the method or path. Tokens are `{body}`, `{timestamp}`, `{method}`, `{path}` and
`{header:Name}`.

**Compound signature headers are first class.** Stripe sends
`t=1614556800,v1=5257a8…,v0=6ffbb5…`. A header name plus a prefix cannot express that, so extracting
a named element from a delimited list is a supported mode — and every matching element is tried,
because Stripe emits one `v1` per active endpoint secret.

**Rotation is not an edge case.** A sender rotating its signing secret emits requests signed with
either secret during the overlap. Verification tries the current secret, then the rotating one while
it is unexpired.

**Failures are indistinguishable to the caller.** One 401, one generic body. The specific
`AuthFailureCode` goes to the trace, never to the sender, because a caller who can tell "malformed"
from "wrong" has an oracle to iterate against.

**Secrets live in the ERP.** `IWebhookSecretProvider` is the extension point; the intended
production implementation reads a `[PXRSACryptString]` field, which is Acumatica's own pattern for
third-party integration credentials. It is encrypted at rest, editable by an administrator without a
redeployment, unaffected by the platform's move off .NET Framework because it is an ORM concern
rather than a configuration-file one, and it is the only option that works on SaaS, where there is
no file system and no environment to read.

## Layout

| Project | Target | Purpose |
|---|---|---|
| `src/…Core` | `netstandard2.0` | Authenticators, templates, crypto primitives. No Acumatica, ASP.NET or `System.Configuration` reference. |
| `tests/…Core.Tests` | `net8.0` | xUnit. No ERP instance required. |

`netstandard2.0` is deliberate: it is consumable from the net48 runtime Acumatica 2025 R2 uses
*and* from .NET 8+ once Acumatica completes its migration, so the assembly does not need
re-targeting or forking when that lands.

The platform binding — `IWebhookHandler`, the DAC-backed secret provider, the maintenance screen —
lands in a separate `net48` adapter assembly that references `PX.*` from the site's `Bin`. Keeping
it out of the core is what makes the entire authentication surface unit-testable without an ERP.

## Tests

```
dotnet test
```

The vectors in `SenderVectorTests` are the tests that matter. GitHub's known-good pair is the one
published in their own documentation, which makes it an external anchor rather than a value this
library computed for itself. Everything else here is conventional code; what silently breaks an
integration is a signature scheme composed slightly wrong.

Timing safety is asserted structurally — that `FixedTimeComparer.AreEqual` keeps the attributes
preventing the JIT from short-circuiting its accumulator loop — rather than by wall-clock
measurement. Timing assertions flake in CI and get deleted within a quarter.

## Licence

MIT. See [LICENSE](LICENSE).
