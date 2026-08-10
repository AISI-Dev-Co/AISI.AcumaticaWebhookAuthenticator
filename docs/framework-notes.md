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

### Members exercised by the official sample

| Member | Observed use |
|---|---|
| `context.Request.Headers.TryGetValue(name, out var value)` | ASP.NET Core `IHeaderDictionary`; the sample uses `Microsoft.Net.Http.Headers.HeaderNames` |
| `context.Request.CreateTextReader()` | Returns a `TextReader`, wrapped in a `JsonTextReader` |
| `context.Response.StatusCode` | `int`, assigned from `Microsoft.AspNetCore.Http.StatusCodes` |
| `context.Response.CreateTextWriter()` | Returns a `TextWriter` for the response body |

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

These are unresolved. Each needs ten minutes with ILSpy or dotPeek against
`PX.Api.Webhooks.Abstractions.dll` on a 2025 R2 site. They gate the adapter assembly, not the core.

### 1. Does `WebhookContext.Request` expose raw bytes? — blocking

`CreateTextReader()` hands back **already-decoded text**. HMAC verification needs the exact bytes
the sender signed, and re-encoding decoded text is not a lossless round trip for a body carrying a
BOM, a non-UTF-8 charset declared in `Content-Type`, or an invalid byte sequence that decoding
replaces with U+FFFD.

- If a `Stream` or `byte[]` accessor exists, use it and the problem disappears.
- If not, try reflecting over an underlying `HttpRequest` if the context wraps one.
- Failing both, UTF-8 re-encoding is correct for the overwhelming majority of senders and must be
  documented as a limitation. `WebhookSignatureTester` then stops being a convenience and becomes
  the primary support tool.

The core is already written to survive this: `SignedPayloadTemplate` resolves to `byte[]` and
splices the body in verbatim, so no part of the signing path forces the body through a string.

### 2. Are `Method` and `Path` surfaced?

The `{method}` and `{path}` template tokens depend on them. `WebhookAuthContext` accepts null for
both and the tokens fail with their own diagnostic codes rather than a misleading signature
mismatch, so the failure is graceful either way — but coverage of senders that sign the method or
path depends on the answer.

### 3. Can response headers be set?

Only `BASIC` needs this, to return `WWW-Authenticate: Basic realm="…"` alongside a 401. Without it
Basic still functions but is not strictly conformant. Nothing observed in the sample exposes a
response header collection.

### 4. Is the request body pre-buffered?

Decides whether a body-size cap can be enforced before a full read, or whether it has to live in
`web.config` (`maxAllowedContentLength` / `maxRequestLength`) instead.

## Egress note

Acumatica's own documentation could not be consulted while writing this: `help.acumatica.com`,
`community.acumatica.com`, `www.acumatica.com` and the usual third-party blogs are all blocked by
this environment's egress policy. Everything above comes from the GitHub examples repository. If
the documentation becomes reachable, the Open section is worth a second pass before the adapter is
built.
