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
    /// Smoke-test handler using the BASIC scheme, to exercise the <c>WWW-Authenticate</c>
    /// challenge on the 401 path. The stored secret is the whole <c>user:password</c> string.
    /// </summary>
    public class BasicSmokeTestHandler : AuthenticatedWebhookHandlerBase
    {
        /// <inheritdoc/>
        protected override IWebhookAuthenticator CreateAuthenticator(IWebhookSecretProvider secretProvider) =>
            new BasicAuthenticator(secretProvider, realm: "smoke-test");

        /// <inheritdoc/>
        protected override Task ProcessAsync(AuthenticatedWebhookContext context, CancellationToken cancellation)
        {
            context.Response.StatusCode = 200;

            using (TextWriter writer = context.Response.CreateTextWriter())
            {
                writer.Write("{\"ok\":true,\"scheme\":\"BASIC\",\"bytes\":" + context.Body.Length + "}");
            }

            return Task.CompletedTask;
        }
    }
}
