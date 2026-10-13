// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;

namespace AISI.AcumaticaWebhookAuthenticator.Diagnostics
{
    /// <summary>What <see cref="WebhookSignatureTester"/> found, including expected signatures, so never return it over HTTP.</summary>
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

        public bool Matched { get; }

        public string? Misconfiguration { get; }

        public string FailureCode { get; }

        public string TemplatePattern { get; }

        public string SignedPayloadPreview { get; }

        public string? TimestampRaw { get; }

        // Prefix included, with the current secret's signature first and then any live rotating secret's.
        public IReadOnlyList<string> ExpectedSignatures { get; }

        public IReadOnlyList<string> ProvidedSignatures { get; }
    }
}
