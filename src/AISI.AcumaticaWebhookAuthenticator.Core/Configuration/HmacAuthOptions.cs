// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using AISI.AcumaticaWebhookAuthenticator.Signing;

namespace AISI.AcumaticaWebhookAuthenticator.Configuration
{
    /// <summary>Everything needed to verify an HMAC-signed webhook, snapshotted by <see cref="Authentication.HmacAuthenticator"/> at construction so later changes are ignored.</summary>
    public sealed class HmacAuthOptions
    {
        #region Construction
        public HmacAuthOptions(IWebhookSecretProvider secretProvider, string signatureHeader)
        {
            if (string.IsNullOrWhiteSpace(signatureHeader))
            {
                throw new ArgumentException("A signature header name is required.", nameof(signatureHeader));
            }

            SecretProvider = secretProvider ?? throw new ArgumentNullException(nameof(secretProvider));
            SignatureHeader = signatureHeader;
        }
        #endregion

        #region Options
        public IWebhookSecretProvider SecretProvider { get; }

        public string SignatureHeader { get; }

        public HmacAlgorithm Algorithm { get; set; } = HmacAlgorithm.Sha256;

        public SignatureEncoding Encoding { get; set; } = SignatureEncoding.Hex;

        public string? SignaturePrefix { get; set; }

        public SignatureExtraction Extraction { get; set; } = SignatureExtraction.Whole;

        public SignedPayloadTemplate Template { get; set; } = SignedPayloadTemplate.Body;

        // Null when the scheme has no timestamp (HMAC rather than HMACTS).
        public TimestampValidation? Timestamp { get; set; }
        #endregion

        #region Validation
        /// <summary>Describes what is wrong with this configuration, or <see langword="null"/> when it is coherent.</summary>
        public string? DescribeMisconfiguration()
        {
            if (Template is null)
            {
                return "No signed-payload template is configured.";
            }

            if (Extraction is null)
            {
                return "No signature extraction mode is configured.";
            }

            // Otherwise an undefined algorithm is a 500 per request, and an undefined encoding a 401 on every request.
            if (!Enum.IsDefined(typeof(HmacAlgorithm), Algorithm))
            {
                return FormattableString.Invariant($"'{Algorithm}' is not a known HMAC algorithm.");
            }

            if (!Enum.IsDefined(typeof(SignatureEncoding), Encoding))
            {
                return FormattableString.Invariant($"'{Encoding}' is not a known signature encoding.");
            }

            if (Timestamp is object && !Template.ReferencesTimestamp)
            {
                return "A replay window is configured but the signed-payload template '" +
                    Template.Pattern +
                    "' does not include a {timestamp} token, so the signature would not cover the " +
                    "timestamp being validated. Add {timestamp} to the template, or drop the window.";
            }

            if (Timestamp is null && Template.ReferencesTimestamp)
            {
                return "The signed-payload template '" +
                    Template.Pattern +
                    "' includes a {timestamp} token but no timestamp source is configured, so no " +
                    "request could ever be verified. Set HmacAuthOptions.Timestamp.";
            }

            return null;
        }
        #endregion
    }
}
