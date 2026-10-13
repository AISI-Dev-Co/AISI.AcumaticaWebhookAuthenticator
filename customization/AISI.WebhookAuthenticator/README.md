# AISI.WebhookAuthenticator customization package

Everything needed to assemble the importable customization package
(`AISI.WebhookAuthenticator.zip`). The zip is packed locally and never committed or attached to
a release: the adapter DLL it carries can only be compiled against a site's licensed `PX.*`
assemblies.

## What the package contains

| Zip entry | Source | Project item |
| --- | --- | --- |
| `project.xml` | [project.xml](project.xml) (this folder) | all items |
| `Bin/AISI.AcumaticaWebhookAuthenticator.Core.dll` | `src/AISI.AcumaticaWebhookAuthenticator.Core` (`netstandard2.0`) | `File` |
| `Bin/AISI.AcumaticaWebhookAuthenticator.Acumatica.dll` | `src/AISI.AcumaticaWebhookAuthenticator.Acumatica`, built against a site `Bin` | `File` |
| `screens/AS/AS301000/AS301000.ts` / `.html` | [/screens/AS/AS301000](../../screens/AS/AS301000) | `PerTenantFile` |
| `screens/AS/AS301010/AS301010.ts` / `.html` | [/screens/AS/AS301010](../../screens/AS/AS301010) | `PerTenantFile` |

`project.xml` also carries the `Sql` table schemas for `AISIWebhookSecret` and
`AISIWebhookRetry`, plus a site map node and access rights (`ScreenWithRights`) for each screen.
Publishing creates the tables, registers the screens and grants the roles with no manual SQL.
Each site map node opens the Modern UI screen (`SelectedUI="D"`,
`~/Scripts/Screens/<ScreenID>.html`); publishing compiles it from the `PerTenantFile` HTML/TS.
Access rights grant Delete (4) to Administrator and Customizer only.

## Building and packing

Build against the *minimum* supported version's `Bin` and copy both DLLs into this folder's
gitignored `Bin/`:

```bash
dotnet build src/AISI.AcumaticaWebhookAuthenticator.Acumatica -c Release -p:AcumaticaBinPath="<2025 R2 site Bin>"
mkdir -p customization/AISI.WebhookAuthenticator/Bin
cp src/AISI.AcumaticaWebhookAuthenticator.Acumatica/bin/Release/net48/AISI.AcumaticaWebhookAuthenticator.Acumatica.dll \
   src/AISI.AcumaticaWebhookAuthenticator.Core/bin/Release/netstandard2.0/AISI.AcumaticaWebhookAuthenticator.Core.dll \
   customization/AISI.WebhookAuthenticator/Bin/
```

Then stage the layout in the table above and zip it, from the repository root:

```bash
STAGE=$(mktemp -d)
cp -r customization/AISI.WebhookAuthenticator/project.xml customization/AISI.WebhookAuthenticator/Bin "$STAGE/"
mkdir -p "$STAGE/screens/AS"
cp -r screens/AS/AS301000 screens/AS/AS301010 "$STAGE/screens/AS/"
ZIP="$PWD/AISI.WebhookAuthenticator.zip"
(cd "$STAGE" && zip -r "$ZIP" .)
unzip -l AISI.WebhookAuthenticator.zip | grep -Ei 'PX\..*\.dll' && echo "PX assembly in the zip - do not ship it"
```

Never commit the adapter DLL or ship a `PX.*` assembly in the zip.
