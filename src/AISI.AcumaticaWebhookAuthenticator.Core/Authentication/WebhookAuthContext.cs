// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;

namespace AISI.AcumaticaWebhookAuthenticator.Authentication
{
    /// <summary>Inbound request as authenticators see it, where <see cref="Body"/> is the caller's raw array rather than a copy so it must be treated as read-only.</summary>
    public sealed class WebhookAuthContext
    {
        #region Construction and state
        private static readonly IReadOnlyList<string> NoValues = Array.Empty<string>();

        private readonly Dictionary<string, IReadOnlyList<string>> _headers;

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
        public byte[] Body { get; }

        public string? Method { get; }

        public string? Path { get; }

        public DateTimeOffset ReceivedOn { get; }

        public Guid? WebhookId { get; }
        #endregion

        #region Header lookup
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
        /// <summary>Copies multi-valued headers into a case-insensitive dictionary with null values sanitized.</summary>
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

        /// <summary>Converts single-valued headers into a case-insensitive multi-valued dictionary.</summary>
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

        /// <summary>Replaces null header values with empty strings, returning the original list untouched when it has none.</summary>
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
