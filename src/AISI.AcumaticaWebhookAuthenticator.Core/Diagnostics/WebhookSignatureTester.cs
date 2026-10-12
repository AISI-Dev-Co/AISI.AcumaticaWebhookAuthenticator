// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using AISI.AcumaticaWebhookAuthenticator.Signing;

namespace AISI.AcumaticaWebhookAuthenticator.Diagnostics
{
    /// <summary>Explains an HMAC mismatch. Contains expected signatures — never return this over HTTP.</summary>
    public static class WebhookSignatureTester
    {
        /// <summary>Runs verification and reports the intermediate values.</summary>
        /// <param name="options">The configuration to test.</param>
        /// <param name="context">A captured request to test it against.</param>
        /// <returns>The report.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="options"/> or <paramref name="context"/> is null.</exception>
        public static SignatureTestReport Test(HmacAuthOptions options, WebhookAuthContext context)
        {
            if (options is null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Reported rather than thrown: explaining a bad configuration is this tool's job.
            string? problem = options.DescribeMisconfiguration();
            if (problem is object)
            {
                return SignatureTestReport.Misconfigured(problem);
            }

            context.TryGetHeaderValues(options.SignatureHeader, out IReadOnlyList<string> headerValues);
            IReadOnlyList<string> provided = options.Extraction.Extract(headerValues);
            AuthResult outcome = new HmacAuthenticator(options).Authenticate(context);
            WebhookSecret? secret = options.SecretProvider.GetSecret();

            string preview = string.Empty;
            string? timestampRaw = null;
            var expected = new List<string>();

            foreach (HmacAuthenticator.SignatureGroup group in HmacAuthenticator.GroupCandidates(
                context,
                headerValues,
                options.Extraction,
                options.Timestamp))
            {
                timestampRaw ??= group.TimestampRaw;

                TemplateResolution resolution = options.Template.Resolve(
                    context,
                    group.TimestampRaw,
                    capturePreview: true);

                if (!resolution.Success)
                {
                    continue;
                }

                if (preview.Length == 0)
                {
                    preview = resolution.Preview;
                }

                AppendExpected(expected, options, secret, context, resolution);
            }

            return new SignatureTestReport(
                outcome.Succeeded,
                outcome.FailureCode,
                options.Template.Pattern,
                preview,
                timestampRaw,
                expected,
                provided);
        }

        private static void AppendExpected(
            List<string> expected,
            HmacAuthOptions options,
            WebhookSecret? secret,
            WebhookAuthContext context,
            TemplateResolution resolution)
        {
            if (secret is null)
            {
                return;
            }

            IReadOnlyList<byte[]> digests = secret.ComputeDiagnosticDigests(
                options.Algorithm,
                resolution.Bytes,
                context.ReceivedOn);

            foreach (byte[] digest in digests)
            {
                string rendered =
                    (options.SignaturePrefix ?? string.Empty) + SignatureCodec.Encode(digest, options.Encoding);

                if (!expected.Contains(rendered))
                {
                    expected.Add(rendered);
                }
            }
        }
    }
}
