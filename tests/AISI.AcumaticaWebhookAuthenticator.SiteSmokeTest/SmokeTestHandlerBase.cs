// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AISI.AcumaticaWebhookAuthenticator.Acumatica;
using AISI.AcumaticaWebhookAuthenticator.Authentication;

namespace AISI.AcumaticaWebhookAuthenticator.SiteSmokeTest
{
    /// <summary>Answers an authenticated request with 200 and the scheme and body length as JSON.</summary>
    public abstract class SmokeTestHandlerBase : AuthenticatedWebhookHandlerBase
    {
        private readonly string _scheme;

        /// <summary>Creates the handler.</summary>
        /// <param name="scheme">The scheme code echoed in the response.</param>
        /// <param name="maxBodyLength">Body cap in bytes.</param>
        protected SmokeTestHandlerBase(string scheme, int maxBodyLength = BoundedBodyReader.DefaultMaxLength)
            : base(maxBodyLength)
        {
            _scheme = scheme;
        }

        /// <inheritdoc/>
        protected sealed override Task ProcessAsync(AuthenticatedWebhookContext context, CancellationToken cancellation)
        {
            context.Response.StatusCode = 200;

            using (TextWriter writer = context.Response.CreateTextWriter())
            {
                writer.Write("{\"ok\":true,\"scheme\":\"" + _scheme + "\",\"bytes\":" + context.Body.Length + "}");
            }

            return Task.CompletedTask;
        }
    }
}
