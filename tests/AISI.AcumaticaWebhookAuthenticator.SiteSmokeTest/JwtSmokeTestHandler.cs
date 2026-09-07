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
    /// Smoke-test handler using Bearer JWT: HS256, required <c>bh</c> body-hash and
    /// <c>aud</c> = webhook registration id.
    /// </summary>
    public class JwtSmokeTestHandler : AuthenticatedWebhookHandlerBase
    {
        /// <inheritdoc/>
        protected override IWebhookAuthenticator CreateAuthenticator(IWebhookSecretProvider secretProvider) =>
            new JwtAuthenticator(WebhookAuthPresets.JwtBearer(secretProvider));

        /// <inheritdoc/>
        protected override Task ProcessAsync(AuthenticatedWebhookContext context, CancellationToken cancellation)
        {
            context.Response.StatusCode = 200;

            using (TextWriter writer = context.Response.CreateTextWriter())
            {
                writer.Write("{\"ok\":true,\"scheme\":\"JWT\",\"bytes\":" + context.Body.Length + "}");
            }

            return Task.CompletedTask;
        }
    }
}
