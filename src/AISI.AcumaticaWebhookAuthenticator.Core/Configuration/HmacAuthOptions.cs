// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using AISI.AcumaticaWebhookAuthenticator.Signing;

namespace AISI.AcumaticaWebhookAuthenticator.Configuration
{
    /// <summary>
    /// Everything needed to verify an HMAC-signed webhook.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <strong>This type is mutable and is not thread-safe. Build it, hand it to an authenticator,
    /// and stop touching it.</strong> The mutable properties exist for the object-initializer syntax
    /// that makes a scheme readable at a glance; they are not a live configuration channel.
    /// </para>
    /// <para>
    /// <see cref="Authentication.HmacAuthenticator"/> copies every value it needs in its constructor
    /// and never reads this object again. Assignments after construction are silently ignored.
    /// Sharing one instance across several authenticators freezes each at whatever it read. Mutating
    /// on one thread while constructing on another can produce a configuration that never coherently
    /// existed — in particular a <see cref="Template"/> / <see cref="Timestamp"/> pair where the
    /// replay window does not cover the timestamp the template signs.
    /// </para>
    /// <para>
    /// The authenticator built from these options is immutable and safe to share across threads. It
    /// is the object to hold onto; this one is scaffolding.
    /// </para>
    /// </remarks>
    public sealed class HmacAuthOptions
    {
        #region Construction
        /// <summary>Creates options.</summary>
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

        /// <summary>
        /// Prefix the sender puts in front of the signature, e.g. <c>sha256=</c>. Null when there
        /// is none.
        /// </summary>
        public string? SignaturePrefix { get; set; }

        /// <summary>How to get the signature out of the header. Defaults to the whole value.</summary>
        public SignatureExtraction Extraction { get; set; } = SignatureExtraction.Whole;

        /// <summary>What the sender signs. Defaults to the body alone.</summary>
        public SignedPayloadTemplate Template { get; set; } = SignedPayloadTemplate.Body;

        /// <summary>
        /// Replay-window configuration, or null when the scheme has no timestamp. Setting this is
        /// what turns an <c>HMAC</c> scheme into an <c>HMACTS</c> one.
        /// </summary>
        public TimestampValidation? Timestamp { get; set; }
        #endregion

        #region Validation
        /// <summary>
        /// Describes what is wrong with this configuration, or <see langword="null"/> when it is
        /// coherent. A replay window over a timestamp the template does not sign is rejected here.
        /// </summary>
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

            // Undefined enum values are a configuration error, but without this they surface at
            // request time: an unknown algorithm throws out of HmacComputer and becomes a 500, and
            // an unknown encoding makes every decode fail so every request 401s as
            // signature_malformed. Neither reads as "you passed a cast integer".
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
