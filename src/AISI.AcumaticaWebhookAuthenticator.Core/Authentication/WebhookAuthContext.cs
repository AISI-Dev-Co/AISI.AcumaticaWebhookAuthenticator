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

            _headers = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (KeyValuePair<string, IReadOnlyList<string>> header in headers)
            {
                _headers[header.Key] = Sanitize(header.Value);
            }
        }

        /// <summary>Creates a context from single-valued headers.</summary>
        public WebhookAuthContext(
            byte[] body,
            IReadOnlyDictionary<string, string> headers,
            string? method,
            string? path,
            DateTimeOffset receivedOn)
            : this(body, Widen(headers), method, path, receivedOn)
        {
        }
        #endregion

        #region Request data
        /// <summary>
        /// Raw request body bytes, exactly as received. This is the live array the caller supplied,
        /// not a copy; treat it as read-only.
        /// </summary>
        public byte[] Body { get; }

        /// <summary>HTTP method, or <see langword="null"/> when the platform did not surface one.</summary>
        public string? Method { get; }

        /// <summary>Request path, or <see langword="null"/> when the platform did not surface one.</summary>
        public string? Path { get; }

        /// <summary>When the request arrived.</summary>
        public DateTimeOffset ReceivedOn { get; }

        /// <summary>Request headers, matched case-insensitively.</summary>
        public IReadOnlyDictionary<string, IReadOnlyList<string>> Headers => _headers;
        #endregion

        #region Header lookup
        /// <summary>
        /// Looks up every value of a header, case-insensitively.
        /// </summary>
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

        /// <summary>
        /// Looks up a header as a single string, case-insensitively.
        /// </summary>
        /// <param name="name">Header name.</param>
        /// <param name="value">
        /// The header value when present, otherwise <see cref="string.Empty"/>. Never null, so a
        /// caller that ignores the return value cannot end up passing null onward. A repeated header
        /// is joined with "," as HTTP field-value folding specifies — which is what the
        /// <c>{header:Name}</c> template token needs, and why signature extraction uses
        /// <see cref="TryGetHeaderValues"/> instead.
        /// </param>
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

        #region Internals
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
                // The nullable annotations promise non-null values, but the intended caller is a
                // net48 adapter where the compiler enforces nothing. A null slipping through here
                // would surface as an ArgumentNullException inside template resolution - a 500 on
                // the request path, which this library's own rules forbid.
                widened[header.Key] = new[] { header.Value is null ? string.Empty : header.Value };
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

            // Copied only on the rare null-carrying path, so the common case stays allocation-free.
            var cleaned = new string[values.Count];
            for (int i = 0; i < values.Count; i++)
            {
                cleaned[i] = values[i] is null ? string.Empty : values[i];
            }

            return cleaned;
        }
        #endregion
    }
}
