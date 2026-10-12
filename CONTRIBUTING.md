# Contributing

```sh
dotnet test tests/AISI.AcumaticaWebhookAuthenticator.Core.Tests
```

No Acumatica instance is required for that suite: everything testable lives in the core, and CI
builds and tests exactly that. The adapter (`*.Acumatica`) needs licensed `PX.*` assemblies, so it
is built locally against a 2025 R2 or 2026 R1 site `Bin` (`-p:AcumaticaBinPath=…` or the
`ACUMATICA_BIN` environment variable).

New signature schemes need a known-good and a known-bad vector in `SenderVectorTests`, preferably
published by the sender (the GitHub pair comes from GitHub's own docs). Timing safety is asserted
structurally; wall-clock timing tests flake in CI and get deleted.

Do not copy `PX.*` assemblies into the repo, the customization zip, or the nupkg.

## Smoke-testing on a site

`tests/AISI.AcumaticaWebhookAuthenticator.SiteSmokeTest` holds three handlers (GitHub HMAC with a
1 KB body cap, BASIC, and Bearer JWT) that answer an authenticated request with
`{"ok":true,"scheme":…,"bytes":…}`. Build it with `-p:AcumaticaBinPath=<site Bin>`, copy
`AISI.AcumaticaWebhookAuthenticator.SiteSmokeTest.dll` into that `Bin` alongside the published
customization package, register each handler on SM304000, enter its secret on AS301000, and POST
signed, unsigned and oversized requests at the webhook URL. Remove the registrations and the DLL
when done.
