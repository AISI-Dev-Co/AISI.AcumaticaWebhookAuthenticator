// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using AISI.AcumaticaWebhookAuthenticator.Signing;

namespace AISI.AcumaticaWebhookAuthenticator.Configuration
{
    /// <summary>Known sender conventions: GitHub, Shopify, Stripe body-HMAC, and Bearer JWT (token HMAC, not body HMAC).</summary>
    public static class WebhookAuthPresets
    {
        /// <summary>GitHub: <c>X-Hub-Signature-256</c>, hex, <c>sha256=</c> prefix, body only.</summary>
        public static HmacAuthOptions GitHub(IWebhookSecretProvider secretProvider) =>
            new HmacAuthOptions(secretProvider, "X-Hub-Signature-256")
            {
                SignaturePrefix = "sha256=",
            };

        /// <summary>Shopify: <c>X-Shopify-Hmac-Sha256</c>, base64, body only.</summary>
        public static HmacAuthOptions Shopify(IWebhookSecretProvider secretProvider) =>
            new HmacAuthOptions(secretProvider, "X-Shopify-Hmac-Sha256")
            {
                Encoding = SignatureEncoding.Base64,
            };

        /// <summary>Stripe: <c>Stripe-Signature</c> <c>t=</c>/<c>v1=</c>, hex, <c>{timestamp}.{body}</c>, with a five-minute default replay window.</summary>
        public static HmacAuthOptions Stripe(IWebhookSecretProvider secretProvider, TimeSpan? tolerance = null) =>
            new HmacAuthOptions(secretProvider, "Stripe-Signature")
            {
                Extraction = SignatureExtraction.KeyValueElement("v1"),
                Template = SignedPayloadTemplate.TimestampDotBody,
                Timestamp = TimestampValidation.FromSignatureHeaderElement("t", tolerance ?? TimeSpan.FromMinutes(5)),
            };

        /// <summary><c>Authorization: Bearer</c> compact JWT (HS256) requiring <c>exp</c>, <c>aud</c> equal to the webhook registration id, and the <c>bh</c> claim that alone binds the HTTP body.</summary>
        public static JwtAuthOptions JwtBearer(IWebhookSecretProvider secretProvider) =>
            new JwtAuthOptions(secretProvider);

        /// <summary>Same as <see cref="JwtBearer(IWebhookSecretProvider)"/> with an explicit <c>aud</c>, which wins over the webhook id.</summary>
        public static JwtAuthOptions JwtBearer(IWebhookSecretProvider secretProvider, string audience) =>
            new JwtAuthOptions(secretProvider)
            {
                Audience = audience ?? throw new ArgumentNullException(nameof(audience)),
            };
    }
}
