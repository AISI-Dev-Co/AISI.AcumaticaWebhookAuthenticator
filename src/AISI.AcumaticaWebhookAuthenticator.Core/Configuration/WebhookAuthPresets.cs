// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using AISI.AcumaticaWebhookAuthenticator.Signing;

namespace AISI.AcumaticaWebhookAuthenticator.Configuration
{
    /// <summary>Known sender conventions: GitHub, Shopify, Stripe HMAC, and Bearer JWT.</summary>
    public static class WebhookAuthPresets
    {
        /// <summary>GitHub: <c>X-Hub-Signature-256</c>, hex, <c>sha256=</c> prefix, body only.</summary>
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

        /// <summary>Shopify: <c>X-Shopify-Hmac-Sha256</c>, base64, body only.</summary>
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

        /// <summary>Stripe: <c>Stripe-Signature</c> <c>t=</c>/<c>v1=</c>, hex, <c>{timestamp}.{body}</c>. Default replay window is five minutes.</summary>
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

        /// <summary><c>Authorization: Bearer</c> HMAC JWT (HS256), requiring <c>exp</c>.</summary>
        public static JwtAuthOptions JwtBearer(IWebhookSecretProvider secretProvider) =>
            new JwtAuthOptions(secretProvider);
    }
}
