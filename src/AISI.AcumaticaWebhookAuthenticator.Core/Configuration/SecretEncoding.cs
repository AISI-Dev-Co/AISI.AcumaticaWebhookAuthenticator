// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

namespace AISI.AcumaticaWebhookAuthenticator.Configuration
{
    /// <summary>How a secret's text form maps to the key bytes.</summary>
    public enum SecretEncoding
    {
        Utf8 = 0,

        Base64 = 1,

        Hex = 2,

        /// <summary>Standard Webhooks (Svix): base64 key bytes, optionally prefixed <c>whsec_</c>.</summary>
        StandardWebhooks = 3,
    }
}
