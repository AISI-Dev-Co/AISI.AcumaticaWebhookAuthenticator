# Framework notes: `PX.Api.Webhooks.IWebhookHandler`

What the platform actually gives an inbound webhook handler, and what this library therefore has
to work around. Everything in the **Verified** section was read out of Acumatica's own published
source; everything in **Open** is still guesswork and must be settled against the assembly before
the adapter layer is written.

## Source

[`Acumatica/Help-and-Training-Examples`](https://github.com/Acumatica/Help-and-Training-Examples),
which the README describes as the examples accompanying the developer guides at **Version 2026 R1**.
The webhook example lives at `IntegrationDevelopment/Help/ConfiguringWebhooks/` and its project file
is stamped `25.201.0166` — 2025 R2, our minimum supported version.

## Verified

### Interface

```csharp
using PX.Api.Webhooks;

public class TogglWebhookHandler : IWebhookHandler
{
    public async Task HandleAsync(WebhookContext context, CancellationToken cancellation)
}
```

Assembly `PX.Api.Webhooks.Abstractions.dll`, namespace `PX.Api.Webhooks`.

The legacy `PX.Data.Webhooks.IWebhookHandler` was removed in 23R2. Since this library's floor is
2025 R2, only the `PX.Api.Webhooks` shape exists across the whole supported range — **there is no
version drift to abstract over, and no version adapter is needed.**

`HandleAsync` returns `Task`, not a response object. Everything the sender receives is written
through `context.Response` as a side effect. Any result type this library exposes is therefore its
own abstraction, translated into `context.Response` mutations by the adapter.

### `WebhookRequest`

Decompiled from `PX.Api.Webhooks.Abstractions, Version=1.0.0.0`. This is the complete public
surface, not a subset — nothing is elided.

```csharp
namespace PX.Api.Webhooks;

public abstract class WebhookRequest
{
    public virtual string Method { get; }
    public virtual IReadOnlyDictionary<string, StringValues> Query { get; }
    public virtual IReadOnlyDictionary<string, StringValues> Headers { get; }
    public virtual long? ContentLength { get; }
    public virtual string ContentType { get; }
    public virtual Stream Body { get; }

    public TextReader CreateTextReader(Encoding defaultEncoding = null);
    protected virtual TextReader CreateTextReaderCore(Encoding encoding);
}
```

`CreateTextReader` parses `charset` out of `ContentType` via `MediaTypeHeaderValue.TryParse` and
falls back to UTF-8 — confirming that the decoded-text path is charset-dependent, and that reading
`Body` directly is the only way to obtain the bytes a sender actually signed.

Acumatica caps inbound webhook bodies at **1 MB**.

### `WebhookResponse`, `WebhookContext`, `WebhookDefinition`

Decompiled 2026-08-13 from a local site's `Bin\PX.Api.Webhooks.Abstractions.dll` at **26.100.0175**
(2026 R1) and confirmed member-for-member identical at **25.201.0213** (2025 R2) — both ends of the
support matrix. Complete public surface, nothing elided:

```csharp
namespace PX.Api.Webhooks;

public abstract class WebhookResponse
{
    public virtual int StatusCode { get; set; }
    public virtual IDictionary<string, StringValues> Headers { get; }   // mutable dictionary
    public virtual long? ContentLength { get; set; }
    public virtual string ContentType { get; set; }
    public virtual Stream Body { get; }

    public TextWriter CreateTextWriter(string mediaType = "application/json");
    public TextWriter CreateTextWriter(string mediaType, Encoding encoding);
    protected virtual TextWriter CreateTextWriterCore(Encoding encoding);
}

public abstract class WebhookContext
{
    public virtual WebhookDefinition Definition { get; }
    public virtual WebhookRequest Request { get; }
    public virtual WebhookResponse Response { get; }
    public virtual string TraceIdentifier { get; }   // matches HttpContext's identifier when set
}

public abstract class WebhookDefinition
{
    public virtual Guid Id { get; }   // same value as PX.Api.Webhooks.DAC.WebHook.WebHookID
}
```

What that settles for the adapter's response side:

- **Headers are a mutable `IDictionary<string, StringValues>`** — set them by assignment. The
  head-ordering obligation stands: everything before the first body write.
- **`CreateTextWriter(mediaType, encoding)` sets `ContentType` itself** (media type plus `charset`
  via `MediaTypeHeaderValue`). Do not assign `ContentType` separately around a `CreateTextWriter`
  call — last writer wins and they will fight.
- **`StatusCode` is a bare `int`** with no default worth trusting; assign it explicitly on every
  path.
- **`WebhookDefinition.Id` is `WebHook.WebHookID`** — the natural key for per-webhook secret
  lookup, handed to the handler on every invocation. The DAC-backed secret provider keys on it.
- **`WebhookContext.TraceIdentifier`** exists for correlating adapter traces with the platform's
  request log.

### What that settles

- **`Body` is a `Stream`.** Raw bytes are available, so HMAC verification runs against exactly what
  the sender signed. The `CreateTextReader` round trip — and every BOM, charset and invalid-sequence
  failure it would have caused — is avoidable entirely. `SignedPayloadTemplate` resolving to
  `byte[]` is now straightforwardly correct rather than defensive.
- **`Headers` is multi-valued.** `WebhookAuthContext` carries `IReadOnlyList<string>` per header to
  match, so a repeated signature header is extracted from value by value instead of being folded
  into one string by the adapter and split apart again here.
- **`Method` exists**, so the `{method}` template token is supported.
- **`ContentType` and `ContentLength` exist**, which the adapter will want for content-type guards
  and for rejecting oversized bodies before reading them.
- **Response headers are settable** (see the `WebhookResponse` surface below), so
  `WWW-Authenticate` on a 401 is available to the `BASIC` scheme when it lands.
- **The 1 MB cap is enforced by the platform**, so a per-endpoint body-size limit is a refinement
  rather than a necessity, and no `web.config` work is required for a baseline.
- **`Query` exists** and was not anticipated. A `{query:name}` template token is now feasible for
  senders that sign query parameters; not implemented, no known sender needs it yet.
- **There is no `Path`.** See below.

### There is no request path

`WebhookRequest` exposes no path member. A sender that signs the request path — not an exotic
convention — cannot be supported from the platform's request object alone.

`WebhookAuthContext.Path` and the `{path}` token are kept anyway, because the core is host-agnostic
and a consumer who obtains a path from elsewhere can supply one. Under this platform the adapter
will pass null, so a template using `{path}` fails every request with `template_path_unavailable`.
That is a clean, named failure rather than a wrong answer — but it is still a trap if it is only
discovered in production.

**Adapter obligation:** the adapter knows it cannot supply a path, so it must reject a `{path}`
template when the handler is constructed rather than let it fail per request. That needs a
`ReferencesPath` property on `SignedPayloadTemplate`, mirroring the existing `ReferencesTimestamp`.
It is deliberately not added yet: nothing consumes it until the adapter exists, and unused public
API is the same defect as unreachable validation.

### Adapter obligations arising from this surface

- **Read `Body` once into a `byte[]`.** It is a bare `Stream` with no documented seekability, so it
  cannot be relied on for a second pass. The same buffer must feed signature verification and
  payload deserialisation; that is the whole premise of the library.
- **Do not trust `ContentLength` as a size gate.** It is `long?` and is absent under chunked
  transfer encoding. Enforce a cap while reading into a bounded buffer.
- **Do not hand the consumer the stream.** Give them the buffer.
- **Flatten nothing.** `Headers` is already `StringValues`; pass the values through to
  `WebhookAuthContext`'s multi-valued constructor rather than joining them.
- **Set the status code and every response header before writing the body.** `CreateTextWriter()`
  returns a writer over the response stream, and on any conventional implementation the first write
  flushes the response head. A header added afterwards is silently dropped — no exception, no
  warning, just a missing header nobody notices until a sender misbehaves. This holds whatever shape
  the response's header collection turns out to be.

### Registration

A webhook is a row in the `WebHook` table, delivered inside a customisation project as
`Webhook_<Name>.xml`:

```xml
<row WebHookID="8978784f-3ad6-4103-913e-19c742048a8a"
     Name="TogglWebhook"
     Handler="TogglWebhook.TogglWebhookHandler"
     IsActive="1" IsSystem="0"
     RequestLogLevel="0" RequestRetainCount="10"
     NoteID="693bbaaf-fd7a-ed11-8392-586c254ce85b" />
```

Two consequences:

- **The handler type is already registered by the platform.** Any endpoint configuration this
  library adds must not carry a second copy of it; `WebHook.Handler` is the source of truth and a
  duplicate will drift.
- **Acumatica already keeps a request log**, bounded by `RequestLogLevel` and `RequestRetainCount`.
  It has no idempotency, no queue and no replay, so it does not replace anything here — but a
  deployment that also persists payloads elsewhere is storing them twice.

### Build surface

- `net48`, `LangVersion 9.0`, `Nullable enable`.
- Acumatica ships Newtonsoft.Json 13 in `Bin`. Use it rather than `System.Text.Json`.
- References to `PX.*` carry `<Private>False</Private>` so the licensed assemblies are not copied
  into the output. Acumatica's own sample omits this on the `PX.Api.Webhooks.Abstractions`
  reference; do not copy that mistake, and assert it in CI.
- Acumatica publishes no `PX.*` reference assemblies to nuget.org. `px.api.webhooks.abstractions`,
  `px.data`, `px.common` and `px.api` all return `BlobNotFound`; only the unrelated
  `Acumatica.RestClient` exists. A published package must therefore declare **zero** Acumatica
  dependencies and let the consumer supply `Bin` references.

### Consequence for this library

`CryptographicOperations.FixedTimeEquals` is unavailable: it arrived in .NET Standard 2.1 and net48
implements 2.0. `Signing/FixedTimeComparer.cs` supplies the equivalent.

### There is no remote address

Neither `WebhookRequest` nor `WebhookContext` exposes the caller's IP address. An IP allowlist —
on the backlog since the original spec — cannot be implemented from the platform surface. The only
route is a proxy-supplied header such as `X-Forwarded-For`, which the sender controls unless a
trusted proxy overwrites or appends to it; an allowlist built on it is authentication theatre
unless the deployment guarantees that.

**Maintainer decision (2026-08-13): ship it on the forwarded header, documented as requiring a
trusted front proxy.** `IpAllowlistAuthenticator` implements it: the client address is read at
`trustedProxyDepth` from the *right* of the flattened header (the left is the sender's to invent),
ports and brackets are stripped, and anything missing, short or unparseable fails closed. It
decorates another authenticator rather than replacing one — restriction, not authentication — and
the adapter unwraps it when vetting templates and finding the BASIC challenge.

## Open

Nothing. Every type in `PX.Api.Webhooks.Abstractions` has now been read in full — `WebhookRequest`,
`WebhookResponse`, `WebhookContext`, `WebhookDefinition`, `IWebhookHandler` — at both ends of the
support matrix.

## How this was established

`WebhookRequest` was decompiled from `PX.Api.Webhooks.Abstractions.dll` (Version 1.0.0.0) and the
result supplied by the maintainer, because the original working session ran in a cloud container
with no Acumatica installation, no `PX.*` packages on nuget.org, and no egress to Acumatica's
sites.

The remaining types were decompiled directly on 2026-08-13 with `ilspycmd` against local site
installs: `C:\Warranty Claim\WarrantyClaim\Bin` (26.100.0175, 2026 R1) and `C:\bpw\BPW_25_2\Bin`
(25.201.0213, 2025 R2). The two versions' surfaces are identical.
