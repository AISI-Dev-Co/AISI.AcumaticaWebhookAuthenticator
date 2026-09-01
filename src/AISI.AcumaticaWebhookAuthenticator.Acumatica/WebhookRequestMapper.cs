// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using Microsoft.Extensions.Primitives;
using PX.Api.Webhooks;

namespace AISI.AcumaticaWebhookAuthenticator.Acumatica
{
    /// <summary>
    /// Builds a <see cref="WebhookAuthContext"/> from the platform's request object.
    /// </summary>
    internal static class WebhookRequestMapper
    {
        /// <summary>
        /// Maps a request. The body must already have been read: the platform stream is
        /// forward-only, and the buffer that was verified is the buffer that gets processed.
        /// </summary>
        public static WebhookAuthContext Map(WebhookRequest request, byte[] body, DateTimeOffset receivedOn, Guid webhookId)
        {
            if (request is null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            var headers = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);

            // Flatten nothing - a repeated signature header must reach extraction intact. Copied
            // to an array so the context is independent of platform storage reuse; null elements
            // become empty strings at this boundary.
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

            // Path is null: WebhookRequest has no path member, and handler construction rejects
            // {path} templates so it is never consulted.
            return new WebhookAuthContext(body, headers, request.Method, null, receivedOn, webhookId);
        }
    }
}
