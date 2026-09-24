// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using AISI.AcumaticaWebhookAuthenticator.Signing;

namespace AISI.AcumaticaWebhookAuthenticator.Configuration
{
    /// <summary>
    /// Everything needed to verify an HMAC-signed webhook. Mutable and not thread-safe:
    /// <see cref="Authentication.HmacAuthenticator"/> snapshots it at construction and ignores later changes.
    /// </summary>
    public sealed class HmacAuthOptions
    {
        #region Construction
        /// <summary>Creates options.</summary>
        /// <param name="secretProvider">Where the signing secret comes from.</param>
        /// <param name="signatureHeader">Header carrying the signature.</param>
        /// <exception cref="ArgumentNullException"><paramref name="secretProvider"/> is null.</exception>
        /// <exception cref="ArgumentException"><paramref name="signatureHeader"/> is null or blank.</exception>
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
        /// <summary>Where the signing secret comes from.</summary>
        public IWebhookSecretProvider SecretProvider { get; }

        /// <summary>Header carrying the signature.</summary>
        public string SignatureHeader { get; }

        /// <summary>Hash algorithm. Defaults to SHA-256.</summary>
        public HmacAlgorithm Algorithm { get; set; } = HmacAlgorithm.Sha256;

        /// <summary>Wire encoding of the signature. Defaults to hex.</summary>
        public SignatureEncoding Encoding { get; set; } = SignatureEncoding.Hex;

        /// <summary>Prefix the sender puts in front of the signature, e.g. <c>sha256=</c>. Null when there is none.</summary>
        public string? SignaturePrefix { get; set; }

        /// <summary>How to get the signature out of the header. Defaults to the whole value.</summary>
        public SignatureExtraction Extraction { get; set; } = SignatureExtraction.Whole;

        /// <summary>What the sender signs. Defaults to the body alone.</summary>
        public SignedPayloadTemplate Template { get; set; } = SignedPayloadTemplate.Body;

        /// <summary>Replay-window configuration, or null when the scheme has no timestamp (<c>HMAC</c> rather than <c>HMACTS</c>).</summary>
        public TimestampValidation? Timestamp { get; set; }
        #endregion

        #region Validation
        /// <summary>Describes what is wrong with this configuration, or <see langword="null"/> when it is coherent.</summary>
        /// <returns>The problem, or <see langword="null"/>.</returns>
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
