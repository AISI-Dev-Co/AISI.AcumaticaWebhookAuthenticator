// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using AISI.AcumaticaWebhookAuthenticator.Signing;

namespace AISI.AcumaticaWebhookAuthenticator.Diagnostics
{
    /// <summary>
    /// Explains why a signature did or did not match.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every webhook integration begins with an hour of guessing why signatures do not match. This
    /// turns that into a diff: here is the exact string your configuration signed, here is what it
    /// produced, here is what the sender sent.
    /// </para>
    /// <para>
    /// <strong>The report contains the expected signatures and must never be returned in an HTTP
    /// response.</strong> It is for an administrative screen or a developer's test, where the viewer
    /// already has access to the secret. Handing it to a caller would let them derive a valid
    /// signature for a payload of their choosing.
    /// </para>
    /// <para>
    /// The verdict is produced by running the real <see cref="HmacAuthenticator"/> rather than by
    /// re-implementing its decision logic, so the report can never disagree with what production
    /// would have done. The cost is that extraction and hashing run twice per call; for a
    /// manually-invoked diagnostic that is the right trade, and re-implementing the decision to
    /// save it would reintroduce the drift the design avoids.
    /// </para>
    /// </remarks>
    public static class WebhookSignatureTester
    {
        /// <summary>
        /// Runs verification and reports the intermediate values.
        /// </summary>
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

            // Reported, not thrown. Constructing the authenticator would throw here, and a tool whose
            // job is explaining why verification failed should not crash on the most common reason.
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

            if (options.Timestamp is object && options.Timestamp.ReadsFromSignatureHeader)
            {
                // Mirrors the authenticator: each header value carries its own timestamp, so each
                // produces its own signed payload and its own acceptable signatures. Reporting only
                // the first value's would show a legitimate match against the second value beside
                // expected signatures it cannot equal.
                foreach (string headerValue in headerValues)
                {
                    string? valueTimestamp = options.Timestamp.ReadRaw(context, new[] { headerValue });
                    timestampRaw ??= valueTimestamp;

                    TemplateResolution resolution = options.Template.Resolve(
                        context,
                        valueTimestamp,
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
            }
            else
            {
                timestampRaw = options.Timestamp?.ReadRaw(context, headerValues);

                TemplateResolution resolution = options.Template.Resolve(
                    context,
                    timestampRaw,
                    capturePreview: true);

                if (resolution.Success)
                {
                    preview = resolution.Preview;
                    AppendExpected(expected, options, secret, context, resolution);
                }
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
