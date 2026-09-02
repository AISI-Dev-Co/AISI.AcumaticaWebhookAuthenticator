# AISI.WebhookAuthenticator customization package ingredients

Everything needed to assemble the importable Acumatica customization package
(`AISI.WebhookAuthenticator.zip`) — the zip itself is never committed. Assemble it after
building the adapter against a 2025 R2+ site Bin. CI cannot produce that DLL.

## What the package contains

| Zip entry | Source | Project item |
| --- | --- | --- |
| `project.xml` | [project.xml](project.xml) (this folder) | all items |
| `Bin/AISI.AcumaticaWebhookAuthenticator.Core.dll` | built by the workflow (`netstandard2.0`, no Acumatica references) | `File` |
| `Bin/AISI.AcumaticaWebhookAuthenticator.Acumatica.dll` | built locally vs a 25R2+ site Bin — **not in git** | `File` |
| `screens/AS/AS301000/AS301000.ts` / `.html` | [/screens/AS/AS301000](../../screens/AS/AS301000) | `PerTenantFile` |

`project.xml` was extracted verbatim from the customization project on the reference 2026 R1
instance (`CustObject` contents wrapped in `<Customization>`), and matches the layout of a package
exported by the Customization Project Editor: item XML in `project.xml`, file payloads at their
app-relative paths. It also carries the `Sql` custom table schema for `AISIWebhookSecret`, the
site map node, and the screen's access rights (`ScreenWithRights`), so publish creates the table,
registers the screen and grants the roles — no manual SQL.

## Do not commit the adapter DLL

`AISI.AcumaticaWebhookAuthenticator.Acumatica.dll` references licensed `PX.*` assemblies from a
site `Bin`. Acumatica publishes no `PX.*` packages, so CI cannot compile it. A committed blob is
almost never this branch's output — shipping it in the zip is a version lie. Adapter **source**
in `src/AISI.AcumaticaWebhookAuthenticator.Acumatica` is the source of truth.

Build the binary when you pack, against the *minimum* supported version:

```bash
dotnet build src/AISI.AcumaticaWebhookAuthenticator.Acumatica -c Release -p:AcumaticaBinPath="<2025R2 site Bin>"
cp src/AISI.AcumaticaWebhookAuthenticator.Acumatica/bin/Release/net48/AISI.AcumaticaWebhookAuthenticator.Acumatica.dll customization/AISI.WebhookAuthenticator/Bin/
```

The `Bin/` folder is gitignored. Copy the DLL there only to assemble the zip. The release
workflow publishes the Core nupkg from CI; it attaches a customization zip only when that
freshly built adapter DLL is present. Missing DLL = nupkg only, not a zip with a stale binary.

JWT lives in Core (built by CI). Adapter source on this branch (graph `PXGraph<,TPrimary>`, DAC
PK/FK, handler catch, mapper webhook id, XML remarks) is not a 26.100 rebuild of a checked-in
DLL.

## Site map URL

The site map node uses the tenant-agnostic Pages URL `~/Pages/AS/AS301000.aspx`. Access rights
grant Delete (4) to Administrator and Customizer only — the package does not ship a foreign
tenant role catalog. Publishing still compiles the Modern UI from the `PerTenantFile` HTML/TS;
no manual frontend build is needed.
