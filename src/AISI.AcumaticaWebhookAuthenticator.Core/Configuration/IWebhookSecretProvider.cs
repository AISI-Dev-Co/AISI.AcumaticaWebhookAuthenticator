// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

namespace AISI.AcumaticaWebhookAuthenticator.Configuration
{
    /// <summary>Supplies the signing secret, where a null secret means fail closed and never skip authentication.</summary>
    public interface IWebhookSecretProvider
    {
        /// <summary>The secret to verify against, or null when none is configured.</summary>
        WebhookSecret? GetSecret();
    }
}
