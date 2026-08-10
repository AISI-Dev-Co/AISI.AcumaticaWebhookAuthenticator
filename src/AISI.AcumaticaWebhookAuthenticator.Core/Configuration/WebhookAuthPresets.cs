// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using AISI.AcumaticaWebhookAuthenticator.Signing;

namespace AISI.AcumaticaWebhookAuthenticator.Configuration
{
    /// <summary>
    /// Ready-made configurations for senders whose conventions are well known and stable.
    /// </summary>
    /// <remarks>
    /// These exist because the hour every webhook integration loses is the one spent discovering
    /// that a sender base64-encodes rather than hex-encodes, or signs the timestamp as well as the
    /// body. Anything not covered here is still expressible with <see cref="HmacAuthOptions"/>
    /// directly; a preset is a shortcut, not a special case.
    /// </remarks>
    public static class WebhookAuthPresets
    {
        /// <summary>
        /// GitHub: <c>X-Hub-Signature-256</c>, hex, <c>sha256=</c> prefix, body alone.
        /// </summary>
        /// <param name="secretProvider">Where the signing secret comes from.</param>
        /// <returns>The options.</returns>
        public static HmacAuthOptions GitHub(IWebhookSecretProvider secretProvider)
        {
            return new HmacAuthOptions(secretProvider, "X-Hub-Signature-256")
            {
                Algorithm = HmacAlgorithm.Sha256,
                Encoding = SignatureEncoding.Hex,
                SignaturePrefix = "sha256=",
                Template = SignedPayloadTemplate.Body,
            };
        }

        /// <summary>
        /// Shopify: <c>X-Shopify-Hmac-Sha256</c>, base64, no prefix, body alone.
        /// </summary>
        /// <param name="secretProvider">Where the signing secret comes from.</param>
        /// <returns>The options.</returns>
        public static HmacAuthOptions Shopify(IWebhookSecretProvider secretProvider)
        {
            return new HmacAuthOptions(secretProvider, "X-Shopify-Hmac-Sha256")
            {
                Algorithm = HmacAlgorithm.Sha256,
                Encoding = SignatureEncoding.Base64,
                SignaturePrefix = null,
                Template = SignedPayloadTemplate.Body,
            };
        }

        /// <summary>
        /// Stripe: <c>Stripe-Signature</c> carrying <c>t=</c> and one or more <c>v1=</c> elements,
        /// hex, signing <c>{timestamp}.{body}</c>.
        /// </summary>
        /// <param name="secretProvider">Where the signing secret comes from.</param>
        /// <param name="tolerance">
        /// Replay window. Defaults to five minutes, matching Stripe's own published guidance.
        /// </param>
        /// <returns>The options.</returns>
        public static HmacAuthOptions Stripe(IWebhookSecretProvider secretProvider, TimeSpan? tolerance = null)
        {
            return new HmacAuthOptions(secretProvider, "Stripe-Signature")
            {
                Algorithm = HmacAlgorithm.Sha256,
                Encoding = SignatureEncoding.Hex,
                SignaturePrefix = null,
                Extraction = SignatureExtraction.KeyValueElement("v1"),
                Template = SignedPayloadTemplate.TimestampDotBody,
                Timestamp = TimestampValidation.FromSignatureHeaderElement(
                    "t",
                    tolerance ?? TimeSpan.FromMinutes(5)),
            };
        }
    }
}
