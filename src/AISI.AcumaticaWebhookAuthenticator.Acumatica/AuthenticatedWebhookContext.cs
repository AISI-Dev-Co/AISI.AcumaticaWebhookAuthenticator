// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Net.Mime;
using System.Text;
using PX.Api.Webhooks;

namespace AISI.AcumaticaWebhookAuthenticator.Acumatica
{
    /// <summary>The platform webhook context plus the buffered request body, since the request stream is already spent.</summary>
    public sealed class AuthenticatedWebhookContext
    {
        private readonly WebhookContext _platform;

        internal AuthenticatedWebhookContext(WebhookContext platform, byte[] body)
        {
            _platform = platform;
            Body = body;
        }

        public WebhookDefinition Definition => _platform.Definition;

        public WebhookRequest Request => _platform.Request;

        // The first body write flushes the head, so set the status code and headers before writing.
        public WebhookResponse Response => _platform.Response;

        public string TraceIdentifier => _platform.TraceIdentifier;

        // Only HMAC schemes and JWT with a bh claim verified these bytes, while SECRET, BASIC and NONE did not.
        public byte[] Body { get; }

        /// <summary>Decodes <see cref="Body"/> with the declared charset, falling back to UTF-8 like the platform's CreateTextReader.</summary>
        public string GetBodyText()
        {
            Encoding encoding = Encoding.UTF8;

            string? contentType = Request.ContentType;
            if (!string.IsNullOrEmpty(contentType))
            {
                // A sender-controlled bad charset must degrade to UTF-8, never to a 500.
                try
                {
                    string? charSet = new ContentType(contentType).CharSet;
                    if (!string.IsNullOrEmpty(charSet))
                    {
                        encoding = Encoding.GetEncoding(charSet);
                    }
                }
                catch (Exception failure) when (failure is FormatException || failure is ArgumentException)
                {
                }
            }

            return encoding.GetString(Body);
        }
    }
}
