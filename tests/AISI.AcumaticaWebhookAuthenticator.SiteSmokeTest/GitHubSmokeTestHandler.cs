// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Configuration;

namespace AISI.AcumaticaWebhookAuthenticator.SiteSmokeTest
{
    /// <summary>Smoke-tests the GitHub HMAC preset, including the over-limit body path.</summary>
    public class GitHubSmokeTestHandler : SmokeTestHandlerBase
    {
        // A 1 KB cap makes the over-limit path testable without a megabyte payload.
        public GitHubSmokeTestHandler()
            : base("HMAC", maxBodyLength: 1024)
        {
        }

        protected override IWebhookAuthenticator CreateAuthenticator(IWebhookSecretProvider secretProvider) =>
            new HmacAuthenticator(WebhookAuthPresets.GitHub(secretProvider));
    }
}
