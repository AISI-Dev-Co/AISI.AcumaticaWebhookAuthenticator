// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using AISI.AcumaticaWebhookAuthenticator.Configuration;

namespace AISI.AcumaticaWebhookAuthenticator.Tests
{
    /// <summary>
    /// A provider with no secret configured, for the fail-closed tests every scheme has.
    /// </summary>
    internal sealed class NullSecretProvider : IWebhookSecretProvider
    {
        public WebhookSecret? GetSecret() => null;
    }
}
