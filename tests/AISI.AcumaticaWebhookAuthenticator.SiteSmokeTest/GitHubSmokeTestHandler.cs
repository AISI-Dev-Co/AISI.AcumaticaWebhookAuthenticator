// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AISI.AcumaticaWebhookAuthenticator.Acumatica;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Configuration;

namespace AISI.AcumaticaWebhookAuthenticator.SiteSmokeTest
{
    /// <summary>
    /// Smoke-test handler using the GitHub preset: HMAC-SHA256, hex, <c>sha256=</c> prefix in
    /// <c>X-Hub-Signature-256</c>, body alone. The 1 KB body cap exists to make the over-limit
    /// path testable without a megabyte payload.
    /// </summary>
    public class GitHubSmokeTestHandler : AuthenticatedWebhookHandlerBase
    {
        /// <summary>Creates the handler with a deliberately small body cap.</summary>
        public GitHubSmokeTestHandler()
            : base(maxBodyLength: 1024)
        {
        }

        /// <inheritdoc/>
        protected override IWebhookAuthenticator CreateAuthenticator(IWebhookSecretProvider secretProvider) =>
            new HmacAuthenticator(WebhookAuthPresets.GitHub(secretProvider));

        /// <inheritdoc/>
        protected override Task ProcessAsync(AuthenticatedWebhookContext context, CancellationToken cancellation)
        {
            context.Response.StatusCode = 200;

            using (TextWriter writer = context.Response.CreateTextWriter())
            {
                writer.Write("{\"ok\":true,\"scheme\":\"HMAC\",\"bytes\":" + context.Body.Length + "}");
            }

            return Task.CompletedTask;
        }
    }
}
