// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

namespace AISI.AcumaticaWebhookAuthenticator.Configuration
{
    /// <summary>How a secret's text form maps to the key bytes.</summary>
    public enum SecretEncoding
    {
        /// <summary>The text itself, as UTF-8. What most sender dashboards mean by a secret.</summary>
        Utf8 = 0,

        /// <summary>Base64-encoded key bytes.</summary>
        Base64 = 1,

        /// <summary>Hex-encoded key bytes.</summary>
        Hex = 2,

        /// <summary>Standard Webhooks (Svix): base64 key bytes, optionally prefixed <c>whsec_</c>.</summary>
        StandardWebhooks = 3,
    }
}
