# Handover

State of this repository as of 2026-08-13, written for the next working session. The previous
session ran in a cloud container with no Acumatica instance; the next one has the code local,
presumably alongside a site install — which unblocks everything listed under "Not built yet".

## What this is

A webhook signature-verification library for Acumatica ERP. A developer implementing
`PX.Api.Webhooks.IWebhookHandler` inherits authentication instead of hand-writing it: HMAC over
the raw request bytes, signed-payload templates, replay windows, secret rotation overlap,
constant-time comparison, presets for GitHub/Shopify/Stripe.

The scope was deliberately cut from a much larger spec (pipeline, idempotency, queueing, retry,
DLQ, screens) down to authentication only — the thing the repo name describes. Do not resurrect
the larger scope without being asked.

## Current state

- **Branch:** `claude/acuwebhookkit-spec-review-tyx895`, PR #1 (draft)
  <https://github.com/AISI-Dev-Co/AISI.AcumaticaWebhookAuthenticator/pull/1>
- **Built and done:** `src/AISI.AcumaticaWebhookAuthenticator.Core` — the whole authentication
  core. 124 tests in `tests/…Core.Tests`, 0 warnings on a clean build, CI green.
- **Not built yet:** the Acumatica adapter assembly, the DAC-backed secret provider and its
  maintenance screen, `SECRET`/`BASIC`/`JWT`/`NONE` schemes, IP allowlist, NuGet publish.

```sh
dotnet clean && dotnet build -c Release && dotnet test --no-build -c Release
```

Always `dotnet clean` before a verification build: an incremental build once skipped compilation
entirely and produced a false "warning-clean" claim that had to be corrected in the log.

## Decisions already made by the maintainer — do not relitigate

| Decision | Value |
|---|---|
| Minimum Acumatica version | 2025 R2 (matrix: 2025 R2, 2026 R1) |
| Prefixes | `AISI` for DACs, `AS` for screen IDs (Acumatica artifacts only; core library types carry no prefix) |
| Package | `AISI.AcumaticaWebhookAuthenticator.Core` ships on NuGet, named after this repo |
| Licence | MIT, per-file header `// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.` |
| Secret storage | ERP database via `[PXRSACryptString]` DAC field (255-char limit — validate, never truncate). `web.config` rejected: dies with the .NET-Core move and never worked on SaaS |
| All six auth schemes in scope | HMAC, HMACTS (built); SECRET, BASIC, JWT, NONE (to build) |
| `HmacAuthOptions` stays mutable | Risks documented on the type and in README §Lifetime; authenticator snapshots at construction |
| Body not defensively copied | Documented contract on `WebhookAuthContext`; caller must not mutate after handover |
| `WebhookSecret.Matches` (single-digest) kept | Convenience for custom authenticators; delete if still unused when the adapter lands |
| In-flight duplicate handling, redaction etc. | Out of scope — cut with the rest of the pipeline spec |

## Verified framework facts (see docs/framework-notes.md for the full record)

The `PX.Api.Webhooks.WebhookRequest` surface was verified against the **decompiled assembly**
(`PX.Api.Webhooks.Abstractions.dll` v1.0.0.0), supplied by the maintainer. Complete surface:
`Method`, `Query`, `Headers` (`IReadOnlyDictionary<string, StringValues>`), `ContentLength`
(`long?`), `ContentType`, `Body` (`Stream`), `CreateTextReader(Encoding)`.

Load-bearing consequences:

- **`Body` is a `Stream`** → raw signed bytes are available. Never verify against re-encoded
  `CreateTextReader` output.
- **There is NO `Path` member.** `{path}` templates cannot be satisfied under Acumatica.
- **Headers are multi-valued** → the core's `WebhookAuthContext` matches; pass `StringValues`
  through unfolded.
- **1 MB platform cap** on webhook bodies; `ContentLength` is null under chunked encoding, so it
  is not a size gate — cap while reading into a bounded buffer.
- **Response**: status code assignable, `CreateTextWriter()` for body, **headers settable** —
  but the `WebhookResponse` member shapes have NOT been read. **This is the one remaining
  unknown.** With the code local, decompile `WebhookResponse` from the site's
  `Bin\PX.Api.Webhooks.Abstractions.dll` before writing the adapter's response side, and record
  it in framework-notes.md.
- Registration is a `WebHook` table row (`Webhook_<Name>.xml` in the customisation project);
  `WebHook.Handler` owns the type name — never duplicate it in configuration.
- Acumatica has a built-in bounded request log (`RequestLogLevel`, `RequestRetainCount`).
- net48, LangVersion 9, Newtonsoft.Json 13 from `Bin`, every `PX.*` reference `<Private>False</Private>`.
- Acumatica publishes no `PX.*` packages to nuget.org; the package must declare zero Acumatica
  dependencies. CI asserts no `PX.*.dll` inside the `.nupkg` — keep that check.

## Next milestone: the adapter assembly

A separate net48 project (e.g. `src/AISI.AcumaticaWebhookAuthenticator.Acumatica`) referencing
`PX.*` from a site `Bin`. Obligations already established (full list in framework-notes.md):

1. Read `Body` once into a `byte[]` (bounded); the same buffer feeds verification and
   deserialisation; the consumer gets the buffer, never the stream.
2. Pass headers through multi-valued to `WebhookAuthContext`'s primary constructor. Flatten
   nothing.
3. Pass `Method`; pass `null` for path. **Reject a `{path}` template at handler construction**
   (the adapter knows it can never supply one) — this needs a `ReferencesPath` property on
   `SignedPayloadTemplate` mirroring `ReferencesTimestamp`, deliberately not added yet because
   nothing consumes it. Add the two together.
4. Set status code and all response headers **before** the first body write —
   `CreateTextWriter()` flushes the response head; late headers drop silently.
5. Uniform 401 with a generic body on any auth failure; the `AuthFailureCode` goes to `PXTrace`
   only. Never let an exception escape as a 500 for hostile input.
6. `ErpSecretProvider` implements `IWebhookSecretProvider` over a `[PXRSACryptString]` field
   (pattern verified in Acumatica's WooCommerce connector sample: `BCBindingWooCommerce.cs`).
   Cache per request-ish; must be thread-safe.

## Invariants — regressions here are the failures that matter

- Every signature comparison goes through `FixedTimeComparer.AreEqual` (BCL
  `FixedTimeEquals` doesn't exist on net48). `WebhookSecret.MatchesAny` deliberately never
  short-circuits across keys or candidates — early exit is a timing oracle for which secret is
  live.
- Fail closed: null secret ⇒ deny, never unauthenticated fallback.
- Replay window validates **after** the signature matches, against **the timestamp that produced
  the matching payload** (per-header-value pairing for Stripe-style schemes).
- Templates resolve to `byte[]`; the body is spliced verbatim; a single-`{body}` template
  aliases the body buffer (no copy). Never route the body through a string on the signing path.
- Misconfiguration throws at authenticator construction (`DescribeMisconfiguration` is shared
  with the tester, which reports instead of throwing).
- `netstandard2.0` core references nothing from Acumatica/ASP.NET/System.Configuration. Keep it
  that way; platform binding lives in the adapter.
- Sender vectors: known-good + known-bad per scheme, preferring vectors published by the sender
  (the GitHub pair is from GitHub's own docs). JWT (M-next) will need the same treatment, plus
  attention to `Microsoft.IdentityModel.*` binding-redirect conflicts against the site's `Bin` —
  that is the real JWT risk, not the token logic.
- Repo hygiene: one public type per file; analyzers on (`Directory.Build.props` +
  `.editorconfig` — both halves needed, the rules were once inert); warnings-as-errors in src;
  tests kept warning-clean too; LF via `.gitattributes`.

## Review history — the recurring defect patterns

Four review passes ran; every pass found real defects, several introduced by the pass before.
The recurring patterns, in order of frequency:

1. **Checks/config that look live but aren't**: a parameter accepted then ignored; analyzer
   rules with no analyzer enabled; unreachable null-checks; a coherence check bypassable by
   mutating options after construction (fixed by snapshotting).
2. **Half-finished generalisations**: multi-value header extraction widened without widening the
   timestamp pairing; tester reporting `keys[0]` expected signatures while rotation accepted two.
3. **Contracts the annotations can't enforce**: net48 callers passing null through
   non-nullable-annotated parameters (now sanitised at the context boundary).
4. **False verification**: the incremental-build "warning-clean" claim.

When reviewing new work (the adapter especially), look for these first.

## Considered and declined (with reasons — don't "fix" these)

- Tester re-executes the real authenticator (double work): deliberate — the verdict must come
  from the production pipeline so the report can never disagree with it.
- Immutable options type: declined by maintainer; risks documented instead.
- Copying the request body defensively: declined; contract documented.
- `{path}` token removal: kept for host-agnostic callers; adapter must reject it instead.
