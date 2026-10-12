// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;

namespace AISI.AcumaticaWebhookAuthenticator.Authentication
{
    /// <summary>Inbound request as authenticators see it. <see cref="Body"/> is the raw arrival bytes, not a copy.</summary>
    public sealed class WebhookAuthContext
    {
        #region Construction and state
        private static readonly IReadOnlyList<string> NoValues = Array.Empty<string>();

        private readonly Dictionary<string, IReadOnlyList<string>> _headers;

        /// <summary>Creates a context from multi-valued headers.</summary>
        public WebhookAuthContext(
            byte[] body,
            IReadOnlyDictionary<string, IReadOnlyList<string>> headers,
            string? method,
            string? path,
            DateTimeOffset receivedOn,
            Guid? webhookId = null)
            : this(body, Copy(headers), method, path, receivedOn, webhookId)
        {
        }

        /// <summary>Creates a context from single-valued headers.</summary>
        public WebhookAuthContext(
            byte[] body,
            IReadOnlyDictionary<string, string> headers,
            string? method,
            string? path,
            DateTimeOffset receivedOn,
            Guid? webhookId = null)
            : this(body, Widen(headers), method, path, receivedOn, webhookId)
        {
        }

        private WebhookAuthContext(
            byte[] body,
            Dictionary<string, IReadOnlyList<string>> headers,
            string? method,
            string? path,
            DateTimeOffset receivedOn,
            Guid? webhookId)
        {
            Body = body ?? throw new ArgumentNullException(nameof(body));
            _headers = headers;
            Method = method;
            Path = path;
            ReceivedOn = receivedOn;
            WebhookId = webhookId;
        }
        #endregion

        #region Request data
        /// <summary>Raw request body as received: the caller's array, not a copy, so treat it as read-only.</summary>
        public byte[] Body { get; }

        /// <summary>HTTP method, or <see langword="null"/> when the platform did not surface one.</summary>
        public string? Method { get; }

        /// <summary>Request path, or <see langword="null"/> when the platform did not surface one.</summary>
        public string? Path { get; }

        /// <summary>When the request arrived.</summary>
        public DateTimeOffset ReceivedOn { get; }

        /// <summary>The webhook registration this request arrived on, when the host surfaces one.</summary>
        public Guid? WebhookId { get; }
        #endregion

        #region Header lookup
        /// <summary>Looks up every value of a header, case-insensitively.</summary>
        /// <param name="name">Header name.</param>
        /// <param name="values">The values when present, otherwise empty. Never null.</param>
        /// <returns><see langword="true"/> when the header is present with at least one value.</returns>
        public bool TryGetHeaderValues(string name, out IReadOnlyList<string> values)
        {
            if (name is object && _headers.TryGetValue(name, out IReadOnlyList<string> found) && found.Count > 0)
            {
                values = found;
                return true;
            }

            values = NoValues;
            return false;
        }

        /// <summary>Looks up a header as a single string, case-insensitively.</summary>
        /// <param name="name">Header name.</param>
        /// <param name="value">The value, or empty when absent. A repeated header is joined with ",".</param>
        /// <returns><see langword="true"/> when the header is present.</returns>
        public bool TryGetHeader(string name, out string value)
        {
            if (!TryGetHeaderValues(name, out IReadOnlyList<string> values))
            {
                value = string.Empty;
                return false;
            }

            value = values.Count == 1 ? values[0] : string.Join(",", values);
            return true;
        }
        #endregion

        #region Header normalisation
        private static Dictionary<string, IReadOnlyList<string>> Copy(
            IReadOnlyDictionary<string, IReadOnlyList<string>> headers)
        {
            if (headers is null)
            {
                throw new ArgumentNullException(nameof(headers));
            }

            var copy = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (KeyValuePair<string, IReadOnlyList<string>> header in headers)
            {
                copy[header.Key] = Sanitize(header.Value);
            }

            return copy;
        }

        private static Dictionary<string, IReadOnlyList<string>> Widen(
            IReadOnlyDictionary<string, string> headers)
        {
            if (headers is null)
            {
                throw new ArgumentNullException(nameof(headers));
            }

            var widened = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (KeyValuePair<string, string> header in headers)
            {
                // net48 callers get no nullable enforcement; a null must become empty, not a 500.
                widened[header.Key] = new[] { header.Value ?? string.Empty };
            }

            return widened;
        }

        private static IReadOnlyList<string> Sanitize(IReadOnlyList<string>? values)
        {
            if (values is null || values.Count == 0)
            {
                return NoValues;
            }

            bool hasNull = false;
            for (int i = 0; i < values.Count; i++)
            {
                if (values[i] is null)
                {
                    hasNull = true;
                    break;
                }
            }

            if (!hasNull)
            {
                return values;
            }

            var cleaned = new string[values.Count];
            for (int i = 0; i < values.Count; i++)
            {
                cleaned[i] = values[i] ?? string.Empty;
            }

            return cleaned;
        }
        #endregion
    }
}
