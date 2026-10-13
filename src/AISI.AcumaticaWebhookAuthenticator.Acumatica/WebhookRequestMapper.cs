// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using Microsoft.Extensions.Primitives;
using PX.Api.Webhooks;

namespace AISI.AcumaticaWebhookAuthenticator.Acumatica
{
    internal static class WebhookRequestMapper
    {
        /// <summary>Builds a <see cref="WebhookAuthContext"/> from the platform request and its already-read body.</summary>
        public static WebhookAuthContext Map(WebhookRequest request, byte[] body, DateTimeOffset receivedOn, Guid webhookId)
        {
            if (request is null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            var headers = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);

            // Values are copied unflattened, because a repeated signature header must reach extraction intact.
            foreach (KeyValuePair<string, StringValues> header in request.Headers)
            {
                StringValues value = header.Value;
                var values = new string[value.Count];

                for (int i = 0; i < values.Length; i++)
                {
                    values[i] = value[i] ?? string.Empty;
                }

                headers[header.Key] = values;
            }

            // WebhookRequest has no path, and the handler base rejects {path} templates before any request reaches here.
            return new WebhookAuthContext(body, headers, request.Method, null, receivedOn, webhookId);
        }
    }
}
