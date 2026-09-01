# AISI.WebhookAuthenticator customization package ingredients

Everything needed to assemble the importable Acumatica customization package
(`AISI.WebhookAuthenticator.zip`) — the zip itself is never committed; the release workflow
builds it.

## What the package contains

| Zip entry | Source | Project item |
| --- | --- | --- |
| `project.xml` | [project.xml](project.xml) (this folder) | all seven items |
| `Bin/AISI.AcumaticaWebhookAuthenticator.Core.dll` | built by the workflow (`netstandard2.0`, no Acumatica references) | `File` |
| `Bin/AISI.AcumaticaWebhookAuthenticator.Acumatica.dll` | [Bin/](Bin/) — committed, see below | `File` |
| `screens/AS/AS301000/AS301000.ts` / `.html` | [/screens/AS/AS301000](../../screens/AS/AS301000) | `PerTenantFile` |

`project.xml` was extracted verbatim from the customization project on the reference 2026 R1
instance (`CustObject` contents wrapped in `<Customization>`), and matches the layout of a package
exported by the Customization Project Editor: item XML in `project.xml`, file payloads at their
app-relative paths. It also carries the `Sql` custom table schema for `AISIWebhookSecret`, the
site map node, and the screen's access rights (`ScreenWithRights`), so publish creates the table,
registers the screen and grants the roles — no manual SQL.

## The committed adapter DLL

`Bin/AISI.AcumaticaWebhookAuthenticator.Acumatica.dll` is a committed binary, which is unusual on
purpose: it references licensed `PX.*` assemblies from a site `Bin`, which cannot exist on a CI
runner (Acumatica publishes no `PX.*` packages), so CI cannot build it. It contains only this
repository's MIT-licensed code — CI asserts no `PX.*.dll` ever enters an artifact.

**Refresh it whenever the adapter changes**, building against the *minimum* supported version:

```bash
dotnet build src/AISI.AcumaticaWebhookAuthenticator.Acumatica -c Release -p:AcumaticaBinPath="<2025R2 site Bin>"
cp src/AISI.AcumaticaWebhookAuthenticator.Acumatica/bin/Release/net48/AISI.AcumaticaWebhookAuthenticator.Acumatica.dll customization/AISI.WebhookAuthenticator/Bin/
```

The release workflow fails if the committed DLL's assembly version does not match
`Directory.Build.props`. Known limitation: the gate catches a version bump without a rebuild, not
a code change without a version bump — bump the version whenever the adapter changes.

## Site map URL

The site map node uses the tenant-agnostic Pages URL `~/Pages/AS/AS301000.aspx`. Access rights
grant Delete (4) to Administrator and Customizer only — the package does not ship a foreign
tenant role catalog. Publishing still compiles the Modern UI from the `PerTenantFile` HTML/TS;
no manual frontend build is needed.

The committed adapter DLL is the 25R2-floor binary. JWT lives in Core (built by CI). Adapter
source on this branch (graph `PXGraph<,TPrimary>`, DAC PK/FK, handler catch, mapper webhook id,
XML remarks) is the source of truth and is not a 26.100 rebuild of that DLL.
