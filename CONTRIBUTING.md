# Contributing

```sh
dotnet test tests/AISI.AcumaticaWebhookAuthenticator.Core.Tests
```

No Acumatica instance is required for that suite. The adapter (`*.Acumatica`) is verified locally against a 2025 R2 or 2026 R1 site `Bin`.

New signature schemes need a known-good and a known-bad vector in `SenderVectorTests`, preferably published by the sender. Timing safety is asserted structurally; wall-clock timing tests flake in CI and get deleted.

Do not copy `PX.*` assemblies into the repo, the customization zip, or the nupkg.

> Need this published on a SaaS tenant, wired to a live sender, or extended past this scope?
> [AISI Dev Co](https://github.com/AISI-Dev-Co) does scoped Acumatica customisation for VARs.
