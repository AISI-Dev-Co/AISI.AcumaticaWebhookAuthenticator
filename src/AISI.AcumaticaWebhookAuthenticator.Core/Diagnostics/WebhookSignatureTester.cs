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
    /// <strong>The report contains the expected signature and must never be returned in an HTTP
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
            string? timestampRaw = options.Timestamp?.ReadRaw(context, headerValue, options.Extraction);

            TemplateResolution resolution = options.Template.Resolve(context, timestampRaw);
            AuthResult outcome = new HmacAuthenticator(options).Authenticate(context);

            string expected = string.Empty;
            if (resolution.Success)
            {
                WebhookSecret? secret = options.SecretProvider.GetSecret();
                if (secret is not null)
                {
                    IReadOnlyList<byte[]> keys = secret.CandidatesAsOf(context.ReceivedOn);
                    if (keys.Count > 0)
                    {
                        expected = SignatureCodec.Encode(
                            HmacComputer.Compute(options.Algorithm, keys[0], resolution.Bytes),
                            options.Encoding);

                        if (!string.IsNullOrEmpty(options.SignaturePrefix))
                        {
                            expected = options.SignaturePrefix + expected;
                        }
                    }
                }
            }

            return new SignatureTestReport(
                outcome.Succeeded,
                outcome.FailureCode,
                options.Template.Pattern,
                resolution.Preview,
                timestampRaw,
                expected,
                provided);
        }
    }

    /// <summary>
    /// What the signature tester found. See the warning on <see cref="WebhookSignatureTester"/>
    /// before displaying this anywhere.
    /// </summary>
    public sealed class SignatureTestReport
    {
        internal SignatureTestReport(
            bool matched,
            string failureCode,
            string templatePattern,
            string signedPayloadPreview,
            string? timestampRaw,
            string expectedSignature,
            IReadOnlyList<string> providedSignatures)
        {
            Matched = matched;
            FailureCode = failureCode;
            TemplatePattern = templatePattern;
            SignedPayloadPreview = signedPayloadPreview;
            TimestampRaw = timestampRaw;
            ExpectedSignature = expectedSignature;
            ProvidedSignatures = providedSignatures;
        }

        /// <summary>Whether the request authenticated.</summary>
        public bool Matched { get; }

        /// <summary>An <see cref="AuthFailureCode"/> value when it did not.</summary>
        public string FailureCode { get; }

        /// <summary>The template that was applied.</summary>
        public string TemplatePattern { get; }

        /// <summary>The string the template produced, as far as it can be rendered readably.</summary>
        public string SignedPayloadPreview { get; }

        /// <summary>The timestamp as it was read off the wire, when the scheme uses one.</summary>
        public string? TimestampRaw { get; }

        /// <summary>The signature this configuration computed, with any configured prefix applied.</summary>
        public string ExpectedSignature { get; }

        /// <summary>The signatures found on the request.</summary>
        public IReadOnlyList<string> ProvidedSignatures { get; }
    }
}
