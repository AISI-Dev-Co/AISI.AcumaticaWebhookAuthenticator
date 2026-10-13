// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;

namespace AISI.AcumaticaWebhookAuthenticator.Configuration
{
    /// <summary>In-memory secret provider for tests, not for production use.</summary>
    public sealed class StaticSecretProvider : IWebhookSecretProvider
    {
        private readonly WebhookSecret _secret;

        public StaticSecretProvider(WebhookSecret secret)
        {
            _secret = secret ?? throw new ArgumentNullException(nameof(secret));
        }

        public WebhookSecret? GetSecret() => _secret;
    }
}
