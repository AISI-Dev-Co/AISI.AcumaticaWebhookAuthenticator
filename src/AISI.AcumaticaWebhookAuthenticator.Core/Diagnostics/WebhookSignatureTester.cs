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

            context.TryGetHeader(options.SignatureHeader, out string headerValue);
            IReadOnlyList<string> provided = options.Extraction.Extract(headerValue);
            string? timestampRaw = options.Timestamp?.ReadRaw(context, headerValue);

            TemplateResolution resolution = options.Template.Resolve(context, timestampRaw, capturePreview: true);
            AuthResult outcome = new HmacAuthenticator(options).Authenticate(context);

            return new SignatureTestReport(
                outcome.Succeeded,
                outcome.FailureCode,
                options.Template.Pattern,
                resolution.Preview,
                timestampRaw,
                ExpectedSignatures(options, context, resolution),
                provided);
        }

        private static IReadOnlyList<string> ExpectedSignatures(
            HmacAuthOptions options,
            WebhookAuthContext context,
            TemplateResolution resolution)
        {
            if (!resolution.Success)
            {
                return Array.Empty<string>();
            }

            WebhookSecret? secret = options.SecretProvider.GetSecret();
            if (secret is null)
            {
                return Array.Empty<string>();
            }

            IReadOnlyList<byte[]> digests = secret.ComputeDiagnosticDigests(
                options.Algorithm,
                resolution.Bytes,
                context.ReceivedOn);

            var rendered = new List<string>(digests.Count);
            foreach (byte[] digest in digests)
            {
                rendered.Add((options.SignaturePrefix ?? string.Empty) + SignatureCodec.Encode(digest, options.Encoding));
            }

            return rendered;
        }
    }
}
