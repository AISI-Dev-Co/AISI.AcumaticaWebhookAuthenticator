// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AISI.AcumaticaWebhookAuthenticator.Acumatica;
using AISI.AcumaticaWebhookAuthenticator.Acumatica.DAC;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using Microsoft.Extensions.Primitives;
using PX.Api.Webhooks;
using PX.Data;

namespace AISI.AcumaticaWebhookAuthenticator.SiteSmokeTest
{
    /// <summary>Smoke-tests manual retries with the GitHub HMAC preset, failing on <c>X-Retry-Smoke: fail</c> and replaying pending rows on <c>X-Retry-Smoke: replay</c>.</summary>
    public class RetrySmokeTestHandler : AuthenticatedWebhookHandlerBase
    {
        private const string SmokeHeader = "X-Retry-Smoke";
        private const string FailValue = "fail";
        private const string ReplayValue = "replay";

        protected override IWebhookAuthenticator CreateAuthenticator(IWebhookSecretProvider secretProvider) =>
            new HmacAuthenticator(WebhookAuthPresets.GitHub(secretProvider));

        protected override async Task ProcessAsync(AuthenticatedWebhookContext context, CancellationToken cancellation)
        {
            // A retry replays no headers, so a body stored by a failing request succeeds when retried.
            if (HasSmokeValue(context.Request, FailValue))
            {
                throw new InvalidOperationException("Retry smoke: X-Retry-Smoke=fail.");
            }

            int replayed = 0;
            if (HasSmokeValue(context.Request, ReplayValue))
            {
                var graph = PXGraph.CreateInstance<AISIWebhookRetryProc>();
                foreach (AISIWebhookRetry row in graph.Retries.Select())
                {
                    await AISIWebhookRetryProc.ReplayAsync(row, cancellation);
                    replayed++;
                }
            }

            context.Response.StatusCode = 200;

            using (TextWriter writer = context.Response.CreateTextWriter())
            {
                writer.Write(
                    "{\"ok\":true,\"scheme\":\"HMAC\",\"retrySmoke\":true,\"replayed\":" +
                    replayed + ",\"bytes\":" + context.Body.Length + "}");
            }
        }

        /// <summary>Whether any value of the smoke header equals the expected value, ignoring case.</summary>
        private static bool HasSmokeValue(WebhookRequest request, string expected)
        {
            // Walked rather than looked up, because the platform does not promise a case-insensitive header dictionary.
            foreach (KeyValuePair<string, StringValues> header in request.Headers)
            {
                if (!string.Equals(header.Key, SmokeHeader, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                foreach (string? value in header.Value)
                {
                    if (string.Equals(value, expected, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
            }

            return false;
        }
    }
}
