// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;

namespace AISI.AcumaticaWebhookAuthenticator.Configuration
{
    /// <summary>
    /// An <see cref="IWebhookSecretProvider"/> over a secret already in memory.
    /// </summary>
    /// <remarks>
    /// Intended for tests and for the signature tester. Using it in production means a secret
    /// compiled into an assembly, which cannot be rotated without a redeployment and will be
    /// recoverable by anyone who can read the DLL.
    /// </remarks>
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
