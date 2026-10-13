// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Microsoft.Extensions.Primitives;
using PX.Api.Webhooks;

namespace AISI.AcumaticaWebhookAuthenticator.Acumatica
{
    /// <summary>Stand-in platform context for a manual retry, with no headers or query and a response that is captured and discarded.</summary>
    internal sealed class ReplayWebhookContext : WebhookContext
    {
        public ReplayWebhookContext(
            Guid webhookId,
            byte[] body,
            string? method,
            string? contentType,
            string? traceIdentifier)
        {
            Definition = new ReplayDefinition(webhookId);
            Request = new ReplayRequest(body, method, contentType);
            Response = new ReplayResponse();
            TraceIdentifier = traceIdentifier ?? string.Empty;
        }

        public override WebhookDefinition Definition { get; }

        public override WebhookRequest Request { get; }

        public override WebhookResponse Response { get; }

        public override string TraceIdentifier { get; }

        private sealed class ReplayDefinition : WebhookDefinition
        {
            public ReplayDefinition(Guid id)
            {
                Id = id;
            }

            public override Guid Id { get; }
        }

        private sealed class ReplayRequest : WebhookRequest
        {
            public ReplayRequest(byte[] body, string? method, string? contentType)
            {
                Body = new MemoryStream(body, writable: false);
                // Webhook deliveries are POSTs, so a row stored without a method replays as one.
                Method = method ?? "POST";
                ContentType = contentType ?? string.Empty;
                ContentLength = body.LongLength;
                Headers = new Dictionary<string, StringValues>(StringComparer.OrdinalIgnoreCase);
                Query = new Dictionary<string, StringValues>(StringComparer.OrdinalIgnoreCase);
            }

            public override string Method { get; }

            public override IReadOnlyDictionary<string, StringValues> Query { get; }

            public override IReadOnlyDictionary<string, StringValues> Headers { get; }

            public override long? ContentLength { get; }

            public override string ContentType { get; }

            public override Stream Body { get; }
        }

        private sealed class ReplayResponse : WebhookResponse
        {
            private readonly MemoryStream _body = new MemoryStream();
            private readonly Dictionary<string, StringValues> _headers =
                new Dictionary<string, StringValues>(StringComparer.OrdinalIgnoreCase);

            public override int StatusCode { get; set; }

            public override IDictionary<string, StringValues> Headers => _headers;

            public override Stream Body => _body;

            protected override TextWriter CreateTextWriterCore(Encoding encoding) =>
                new StreamWriter(_body, encoding, 1024, leaveOpen: true);
        }
    }
}
