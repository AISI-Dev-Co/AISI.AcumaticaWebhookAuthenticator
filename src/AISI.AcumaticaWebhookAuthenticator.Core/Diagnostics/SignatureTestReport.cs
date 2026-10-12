// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;

namespace AISI.AcumaticaWebhookAuthenticator.Diagnostics
{
    /// <summary>What <see cref="WebhookSignatureTester"/> found. Contains expected signatures — never return this over HTTP.</summary>
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

        /// <summary>Why the configuration could never verify anything, or <see langword="null"/> when it is coherent.</summary>
        public string? Misconfiguration { get; }

        /// <summary>An <see cref="AuthFailureCode"/> value when it did not, otherwise empty.</summary>
        public string FailureCode { get; }

        /// <summary>The template that was applied.</summary>
        public string TemplatePattern { get; }

        /// <summary>The string the template produced, as far as it can be rendered readably.</summary>
        public string SignedPayloadPreview { get; }

        /// <summary>The timestamp as it was read off the wire, when the scheme uses one.</summary>
        public string? TimestampRaw { get; }

        /// <summary>Every signature this configuration would accept, prefix included: the current secret's, then any live rotating secret's.</summary>
        public IReadOnlyList<string> ExpectedSignatures { get; }

        /// <summary>The signatures found on the request.</summary>
        public IReadOnlyList<string> ProvidedSignatures { get; }
    }
}
