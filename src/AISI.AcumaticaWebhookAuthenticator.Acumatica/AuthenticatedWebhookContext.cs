// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Net.Mime;
using System.Text;
using PX.Api.Webhooks;

namespace AISI.AcumaticaWebhookAuthenticator.Acumatica
{
    /// <summary>
    /// What an authenticated handler gets to work with: the platform context plus the verified
    /// body buffer.
    /// </summary>
    /// <remarks>
    /// <see cref="Body"/> is the buffer the signature was verified against. Deserialise from it and
    /// nothing else — <c>Request.Body</c> has already been consumed and
    /// <c>Request.CreateTextReader()</c> would read from that spent stream. The buffer is shared,
    /// not copied; do not mutate it.
    /// </remarks>
    public sealed class AuthenticatedWebhookContext
    {
        private readonly WebhookContext _platform;

        internal AuthenticatedWebhookContext(WebhookContext platform, byte[] body)
        {
            _platform = platform;
            Body = body;
        }

        /// <summary>The webhook registration this request arrived on.</summary>
        public WebhookDefinition Definition => _platform.Definition;

        /// <summary>The platform request. Its stream is spent; use <see cref="Body"/>.</summary>
        public WebhookRequest Request => _platform.Request;

        /// <summary>The response to write. Set the status code and every header before the first body write.</summary>
        public WebhookResponse Response => _platform.Response;

        /// <summary>The platform's trace correlation identifier.</summary>
        public string TraceIdentifier => _platform.TraceIdentifier;

        /// <summary>The raw request body — the exact bytes the signature verified. Treat as read-only.</summary>
        public byte[] Body { get; }

        /// <summary>
        /// Decodes <see cref="Body"/> as text using the request's declared charset, falling back to
        /// UTF-8 — the same fallback the platform's own <c>CreateTextReader</c> applies.
        /// </summary>
        /// <returns>The body as text.</returns>
        public string GetBodyText()
        {
            Encoding encoding = Encoding.UTF8;

            string? contentType = Request.ContentType;
            if (!string.IsNullOrEmpty(contentType))
            {
                // Both parses can fail on sender-controlled input; a bad charset must degrade to
                // the UTF-8 fallback, never to a 500.
                try
                {
                    string? charSet = new ContentType(contentType).CharSet;
                    if (!string.IsNullOrEmpty(charSet))
                    {
                        encoding = Encoding.GetEncoding(charSet);
                    }
                }
                catch (FormatException)
                {
                }
                catch (ArgumentException)
                {
                }
            }

            return encoding.GetString(Body);
        }
    }
}
