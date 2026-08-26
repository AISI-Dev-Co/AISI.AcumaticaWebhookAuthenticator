// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;

namespace AISI.AcumaticaWebhookAuthenticator.Configuration
{
    /// <summary>In-memory secret provider for tests. Do not use in production.</summary>
    public sealed class StaticSecretProvider : IWebhookSecretProvider
    {
        private readonly WebhookSecret _secret;

        /// <summary>Creates a provider over a fixed secret.</summary>
        /// <param name="secret">The secret to return.</param>
        /// <exception cref="ArgumentNullException"><paramref name="secret"/> is null.</exception>
        public StaticSecretProvider(WebhookSecret secret)
        {
            _secret = secret ?? throw new ArgumentNullException(nameof(secret));
        }

        /// <inheritdoc/>
        public WebhookSecret? GetSecret() => _secret;
    }
}
