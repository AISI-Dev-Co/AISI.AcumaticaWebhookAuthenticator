// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

namespace AISI.AcumaticaWebhookAuthenticator.Signing
{
    /// <summary>
    /// Hash algorithm underlying an HMAC signature scheme.
    /// </summary>
    public enum HmacAlgorithm
    {
        /// <summary>HMAC-SHA256. The correct default; used by GitHub, Shopify, Stripe and most others.</summary>
        Sha256 = 0,

        /// <summary>
        /// HMAC-SHA1. Supported only because a number of long-lived senders still emit it.
        /// Do not choose it for a new integration.
        /// </summary>
        Sha1 = 1,

        /// <summary>HMAC-SHA512.</summary>
        Sha512 = 2,
    }
}
