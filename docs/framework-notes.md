# Framework notes: `PX.Api.Webhooks.IWebhookHandler`

What the platform gives an inbound webhook handler, and how the adapter
(`src/AISI.AcumaticaWebhookAuthenticator.Acumatica`) handles each part of it.

## Sources

- Acumatica's webhook example in
  [`Acumatica/Help-and-Training-Examples`](https://github.com/Acumatica/Help-and-Training-Examples)
  (`IntegrationDevelopment/Help/ConfiguringWebhooks/`, project stamped `25.201.0166`).
- `PX.Api.Webhooks.Abstractions.dll` (assembly version 1.0.0.0), decompiled from site `Bin`
  folders at **25.201.0213** (2025 R2) and **26.100.0175** (2026 R1). Every public type in it —
  `IWebhookHandler`, `WebhookContext`, `WebhookRequest`, `WebhookResponse`, `WebhookDefinition` —
  is member-for-member identical at both versions.

## Interface

```csharp
namespace PX.Api.Webhooks;

public interface IWebhookHandler
{
    Task HandleAsync(WebhookContext context, CancellationToken cancellation);
}
```

The legacy `PX.Data.Webhooks.IWebhookHandler` was removed in 2023 R2, so only this shape exists
across the supported range and no version shim is needed.

`HandleAsync` returns `Task`, not a response object: everything the sender receives is written
through `context.Response`. `AuthenticatedWebhookHandlerBase` implements it and writes the 401
and 413 responses itself.

## API surface

Complete public surface, nothing elided.

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

## What the platform provides, and what the adapter does with it

### Request

- **`Body` is a forward-only `Stream`.** The adapter reads it once, through
  `BoundedBodyReader`, into a `byte[]`; that buffer is what gets verified and what the handler
  receives as `AuthenticatedWebhookContext.Body`. The consumer never gets the stream.
- **`CreateTextReader` decodes by the `ContentType` charset** (via `MediaTypeHeaderValue.TryParse`,
  falling back to UTF-8), so it cannot yield the bytes a sender signed. Signed payloads are built
  as `byte[]` with the raw body spliced in; `AuthenticatedWebhookContext.GetBodyText()` offers the
  same charset-with-UTF-8-fallback decoding for consumers who want text.
- **The platform caps bodies at 1 MB.** `BoundedBodyReader.DefaultMaxLength` matches it; a handler
  can pass a tighter cap to the base constructor. Over-cap requests get a 413 before any secret is
  read.
- **`ContentLength` is `long?`**, absent under chunked encoding and sender-controlled when present.
  The adapter uses it only as a buffer-size hint and a fast reject; the cap is enforced while
  reading.
- **`Headers` is multi-valued.** `WebhookRequestMapper` copies every value into
  `WebhookAuthContext` without joining them, so a repeated signature header reaches extraction
  intact.
- **`Method` exists**, so the `{method}` template token is supported.
- **`Query` exists.** No template token uses it; no known sender signs query parameters.

### There is no request path

`WebhookRequest` exposes no path member, so the adapter passes a null path. A signed-payload
template containing `{path}` could never verify: `HmacAuthenticator` reports it through
`IRequestPathDependent.RequiresRequestPath` (from `SignedPayloadTemplate.ReferencesPath`), and
the handler base throws `InvalidOperationException` on the registration's first request instead
of denying every request as an apparent sender problem. The core keeps `{path}` for hosts that
can supply one.

### There is no remote address

Neither `WebhookRequest` nor `WebhookContext` exposes the caller's IP address, so an allowlist can
only read a forwarded header such as `X-Forwarded-For` — meaningful only behind a trusted front
proxy that writes it. `IpAllowlistAuthenticator` reads the client address `trustedProxyDepth`
entries from the *right* of the flattened header (the left is the sender's to invent), strips
ports and brackets, and fails closed on anything missing, short or unparseable.

It decorates another authenticator rather than replacing one, and forwards the inner scheme's
`IChallengeSource.Challenge` and `IRequestPathDependent.RequiresRequestPath`, so wrapping never
hides a `BASIC` challenge or a `{path}` template. `ErpSecretProvider` applies the allowlist stored
on AS301000 per request (via `IAuthenticatorRefiner`) and substitutes a deny-all authenticator
when the stored list cannot be parsed.

### Response

- **`StatusCode` is a bare `int`**; the adapter assigns it explicitly on every path it writes.
- **`Headers` is a mutable `IDictionary<string, StringValues>`**, set by assignment
  (`WWW-Authenticate` for `BASIC` and `JWT`).
- **Status and headers must precede the first body write.** `CreateTextWriter()` writes to the
  response stream, and the first write flushes the head; a header set afterwards is silently
  dropped. The adapter's `Deny` sets both before creating the writer.
- **`CreateTextWriter(mediaType, encoding)` sets `ContentType` itself** (media type plus
  `charset`). Do not also assign `ContentType` around the call; the last writer wins.

### Definition and tracing

- **`WebhookDefinition.Id` is `WebHook.WebHookID`**, handed over on every request. It keys the
  `AISIWebhookSecret` row, the per-registration authenticator cache and JWT audience binding.
- **`WebhookContext.TraceIdentifier`** correlates with the platform's request log; the handler
  base includes it in its `PXTrace` warnings.

## Registration

A webhook is a row in the `WebHook` table, delivered in a customization project as
`Webhook_<Name>.xml`:

```xml
<row WebHookID="8978784f-3ad6-4103-913e-19c742048a8a"
     Name="TogglWebhook"
     Handler="TogglWebhook.TogglWebhookHandler"
     IsActive="1" IsSystem="0"
     RequestLogLevel="0" RequestRetainCount="10"
     NoteID="693bbaaf-fd7a-ed11-8392-586c254ce85b" />
```

- **`WebHook.Handler` is the source of truth for the handler type.** The library stores no second
  copy; `AISIWebhookSecret` holds only authentication configuration, keyed by `WebHookID`.
- **Acumatica already keeps a request log**, bounded by `RequestLogLevel` and
  `RequestRetainCount`. It has no idempotency, queue or replay.

## Build surface

- The adapter targets `net48` with `LangVersion 9.0` and `Nullable enable`.
- Acumatica publishes no `PX.*` reference assemblies to nuget.org (`px.api.webhooks.abstractions`,
  `px.data`, `px.common` and `px.api` all return `BlobNotFound`), so the adapter compiles against
  a site `Bin` and ships in the customization package, not as a NuGet package.
- Every `PX.*` reference carries `<Private>False</Private>` so no licensed assembly reaches the
  output; Acumatica's own sample omits it on `PX.Api.Webhooks.Abstractions`. CI asserts that the
  nupkg contains no `PX.*` assembly.
- The core targets `netstandard2.0`, which lacks `CryptographicOperations.FixedTimeEquals`
  (.NET Standard 2.1+); `Signing/FixedTimeComparer.cs` supplies the equivalent.
