// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;

namespace AISI.AcumaticaWebhookAuthenticator.Authentication
{
    /// <summary>
    /// The inbound request as an authenticator sees it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="Body"/> is the <em>raw bytes as they arrived</em>. Signature verification is
    /// performed against this buffer and nothing else. Deserialising the payload and re-serialising
    /// it produces different bytes — different key order, different whitespace, different number
    /// formatting — and breaks every HMAC scheme in existence. Read the body once, verify against the
    /// buffer, deserialise from the same buffer.
    /// </para>
    /// <para>
    /// This type deliberately has no dependency on Acumatica or ASP.NET. The adapter assembly builds
    /// one of these from the platform's request object, which keeps the whole authentication surface
    /// unit-testable without an ERP instance.
    /// </para>
    /// </remarks>
    public sealed class WebhookAuthContext
    {
        private readonly IReadOnlyDictionary<string, string> _headers;

        /// <summary>
        /// Creates a context.
        /// </summary>
        /// <param name="body">Raw request body bytes, exactly as received.</param>
        /// <param name="headers">
        /// Request headers. Matched case-insensitively regardless of the comparer on the dictionary
        /// passed in. A header with multiple values should be joined with "," by the caller, which is
        /// what HTTP field-value folding specifies.
        /// </param>
        /// <param name="method">HTTP method, e.g. "POST". Optional; only needed by templates using <c>{method}</c>.</param>
        /// <param name="path">Request path, e.g. "/api/webhooks/…". Optional; only needed by templates using <c>{path}</c>.</param>
        /// <param name="receivedOn">
        /// When the request arrived. Supplied rather than read from the clock so that replay-window
        /// behaviour is deterministic under test.
        /// </param>
        /// <exception cref="ArgumentNullException"><paramref name="body"/> or <paramref name="headers"/> is null.</exception>
        public WebhookAuthContext(
            byte[] body,
            IReadOnlyDictionary<string, string> headers,
            string? method,
            string? path,
            DateTimeOffset receivedOn)
        {
            if (headers is null)
            {
                throw new ArgumentNullException(nameof(headers));
            }

            Body = body ?? throw new ArgumentNullException(nameof(body));
            Method = method;
            Path = path;
            ReceivedOn = receivedOn;

            var caseInsensitive = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (KeyValuePair<string, string> header in headers)
            {
                caseInsensitive[header.Key] = header.Value;
            }

            _headers = caseInsensitive;
        }

        /// <summary>Raw request body bytes, exactly as received.</summary>
        public byte[] Body { get; }

        /// <summary>HTTP method, or <see langword="null"/> when the platform did not surface one.</summary>
        public string? Method { get; }

        /// <summary>Request path, or <see langword="null"/> when the platform did not surface one.</summary>
        public string? Path { get; }

        /// <summary>When the request arrived.</summary>
        public DateTimeOffset ReceivedOn { get; }

        /// <summary>Request headers, matched case-insensitively.</summary>
        public IReadOnlyDictionary<string, string> Headers => _headers;

        /// <summary>
        /// Looks up a header by name, case-insensitively.
        /// </summary>
        /// <param name="name">Header name.</param>
        /// <param name="value">
        /// The header value when present, otherwise <see cref="string.Empty"/>. Never null, so a
        /// caller that ignores the return value cannot end up passing null onward.
        /// </param>
        /// <returns><see langword="true"/> when the header is present.</returns>
        public bool TryGetHeader(string name, out string value)
        {
            if (name is object && _headers.TryGetValue(name, out string found))
            {
                value = found;
                return true;
            }

            value = string.Empty;
            return false;
        }
    }
}
