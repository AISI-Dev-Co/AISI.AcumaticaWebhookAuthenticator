// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using Microsoft.Extensions.Primitives;
using PX.Api.Webhooks;

namespace AISI.AcumaticaWebhookAuthenticator.Acumatica
{
    /// <summary>
    /// Builds a <see cref="WebhookAuthContext"/> from the platform's request object. Internal:
    /// its one caller is <see cref="AuthenticatedWebhookHandlerBase"/>, and public API with no
    /// consumer is the same defect as unreachable validation.
    /// </summary>
    internal static class WebhookRequestMapper
    {
        /// <summary>
        /// Maps a request. The body must already have been read — by
        /// <see cref="BoundedBodyReader"/> — because the platform stream is forward-only and this
        /// library's contract is that the buffer that was verified is the buffer that gets
        /// processed.
        /// </summary>
        /// <param name="request">The platform request.</param>
        /// <param name="body">The raw body bytes, exactly as received.</param>
        /// <param name="receivedOn">When the request arrived.</param>
        /// <returns>The context to authenticate.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="request"/> or <paramref name="body"/> is null.</exception>
        public static WebhookAuthContext Map(WebhookRequest request, byte[] body, DateTimeOffset receivedOn)
        {
            if (request is null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            var headers = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);

            // Flatten nothing: each StringValues is handed over value by value, so a repeated
            // signature header reaches extraction intact. Copied to an array rather than boxed so
            // the context is independent of any later platform reuse of the underlying storage;
            // a null element becomes an empty string here rather than by suppressing the
            // annotation and leaning on the core's last-resort sanitiser.
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

            // Path is null and stays null: WebhookRequest has no path member. Handler construction
            // rejects {path} templates so this null is never consulted.
            return new WebhookAuthContext(body, headers, request.Method, null, receivedOn);
        }
    }
}
