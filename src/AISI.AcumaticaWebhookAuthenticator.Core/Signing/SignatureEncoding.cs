// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

namespace AISI.AcumaticaWebhookAuthenticator.Signing
{
    /// <summary>
    /// Wire encoding a sender uses to represent a signature digest in a header value.
    /// </summary>
    public enum SignatureEncoding
    {
        /// <summary>Lowercase hexadecimal. Used by GitHub and Stripe.</summary>
        Hex = 0,

        /// <summary>Standard base64 with padding. Used by Shopify.</summary>
        Base64 = 1,
    }
}
