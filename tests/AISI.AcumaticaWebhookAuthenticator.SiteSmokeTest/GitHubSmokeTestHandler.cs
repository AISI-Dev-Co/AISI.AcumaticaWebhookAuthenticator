// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Configuration;

namespace AISI.AcumaticaWebhookAuthenticator.SiteSmokeTest
{
    /// <summary>
    /// GitHub preset (HMAC-SHA256 of the body, hex, <c>sha256=</c> in <c>X-Hub-Signature-256</c>).
    /// The 1 KB body cap makes the over-limit path testable without a megabyte payload.
    /// </summary>
    public class GitHubSmokeTestHandler : SmokeTestHandlerBase
    {
        /// <summary>Creates the handler with a deliberately small body cap.</summary>
        public GitHubSmokeTestHandler()
            : base("HMAC", maxBodyLength: 1024)
        {
        }

        /// <inheritdoc/>
        protected override IWebhookAuthenticator CreateAuthenticator(IWebhookSecretProvider secretProvider) =>
            new HmacAuthenticator(WebhookAuthPresets.GitHub(secretProvider));
    }
}
