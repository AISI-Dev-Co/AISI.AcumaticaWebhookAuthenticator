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

On the response side, `context.Response.StatusCode` is an `int` assigned from
`Microsoft.AspNetCore.Http.StatusCodes`, `CreateTextWriter()` returns a `TextWriter` for the body,
and **response headers can be set**.

Acumatica caps inbound webhook bodies at **1 MB**.

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
- **Response headers are settable**, so `WWW-Authenticate` on a 401 is available to the `BASIC`
  scheme when it lands.
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

## Open

Nothing on `WebhookRequest`. The remaining unknown is the `WebhookResponse` surface, which the
adapter needs in order to set a status code, write a body and add headers. Response headers are
confirmed settable; the exact member shapes have not been read.

## How this was established

`PX.Api.Webhooks.Abstractions.dll` (Version 1.0.0.0) was decompiled and the result supplied by the
maintainer.

It could not be decompiled here. This repository is built in a cloud container with no Acumatica
installation, so there is no site `Bin` to read from; Acumatica publishes no `PX.*` packages to
nuget.org (`px.api.webhooks.abstractions`, `px.data`, `px.common` and `px.api` all return
`BlobNotFound`); and `help.acumatica.com`, `community.acumatica.com` and `www.acumatica.com` are
blocked by the container's egress policy. Decompilation needs the binary, and there was no route to
one.

The lesson for the next unknown is to ask for the artefact directly rather than record the question
and work around it. Everything in the Verified section above that predates this note came from the
public examples repository, which was the best available substitute and was materially less
complete.
