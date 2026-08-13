// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;

namespace AISI.AcumaticaWebhookAuthenticator.Diagnostics
{
    /// <summary>
    /// What <see cref="WebhookSignatureTester"/> found.
    /// </summary>
    /// <remarks>
    /// This carries the expected signatures and must never be returned in an HTTP response. See the
    /// warning on <see cref="WebhookSignatureTester"/>.
    /// </remarks>
    public sealed class SignatureTestReport
    {
        internal SignatureTestReport(
            bool matched,
            string failureCode,
            string templatePattern,
            string signedPayloadPreview,
            string? timestampRaw,
            IReadOnlyList<string> expectedSignatures,
            IReadOnlyList<string> providedSignatures,
            string? misconfiguration = null)
        {
            Misconfiguration = misconfiguration;
            Matched = matched;
            FailureCode = failureCode;
            TemplatePattern = templatePattern;
            SignedPayloadPreview = signedPayloadPreview;
            TimestampRaw = timestampRaw;
            ExpectedSignatures = expectedSignatures;
            ProvidedSignatures = providedSignatures;
        }

        /// <summary>
        /// Builds a report for a configuration that could never verify anything.
        /// </summary>
        /// <param name="problem">What is wrong, from <see cref="Configuration.HmacAuthOptions.DescribeMisconfiguration"/>.</param>
        /// <returns>The report.</returns>
        internal static SignatureTestReport Misconfigured(string problem) =>
            new SignatureTestReport(
                false,
                AuthFailureCode.Misconfigured,
                string.Empty,
                string.Empty,
                null,
                Array.Empty<string>(),
                Array.Empty<string>(),
                problem);

        /// <summary>Whether the request authenticated.</summary>
        public bool Matched { get; }

        /// <summary>
        /// What is wrong with the configuration itself, when nothing about the request could have
        /// made it verify. <see langword="null"/> when the configuration is coherent.
        /// </summary>
        public string? Misconfiguration { get; }

        /// <summary>An <see cref="AuthFailureCode"/> value when it did not, otherwise empty.</summary>
        public string FailureCode { get; }

        /// <summary>The template that was applied.</summary>
        public string TemplatePattern { get; }

        /// <summary>The string the template produced, as far as it can be rendered readably.</summary>
        public string SignedPayloadPreview { get; }

        /// <summary>The timestamp as it was read off the wire, when the scheme uses one.</summary>
        public string? TimestampRaw { get; }

        /// <summary>
        /// Every signature this configuration would accept, with any configured prefix applied: the
        /// current secret's first, then the rotating secret's when a rotation overlap is live.
        /// </summary>
        /// <remarks>
        /// A list rather than a single value because reporting only the current secret's digest made
        /// a request legitimately signed with the retiring secret display as matched next to an
        /// expected signature that appears nowhere on the request.
        /// </remarks>
        public IReadOnlyList<string> ExpectedSignatures { get; }

        /// <summary>The signatures found on the request.</summary>
        public IReadOnlyList<string> ProvidedSignatures { get; }
    }
}
