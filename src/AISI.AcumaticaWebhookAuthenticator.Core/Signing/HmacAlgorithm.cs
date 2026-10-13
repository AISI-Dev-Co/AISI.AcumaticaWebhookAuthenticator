// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

namespace AISI.AcumaticaWebhookAuthenticator.Signing
{
    /// <summary>Hash algorithm underlying an HMAC signature scheme.</summary>
    public enum HmacAlgorithm
    {
        Sha256 = 0,

        // Legacy senders only; never choose SHA-1 for a new integration.
        Sha1 = 1,

        Sha512 = 2,
    }
}
