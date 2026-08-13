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
    /// Headers are multi-valued, mirroring the <c>StringValues</c> that
    /// <c>PX.Api.Webhooks.WebhookRequest.Headers</c> exposes. A repeated header therefore arrives
    /// intact rather than folded into one string and split apart again downstream.
    /// </para>
    /// <para>
    /// <see cref="Body"/> is <em>not</em> defensively copied, unlike the key material in
    /// <see cref="Configuration.WebhookSecret"/>. The asymmetry is deliberate: a copy per request
    /// would double the allocation and memory traffic of every payload the ERP receives, and unlike
    /// a secret the body is neither confidential to this library nor long-lived. The contract that
    /// falls out of it is that <strong>the caller must not mutate the array after handing it over,
    /// and must not share it with anything that might</strong>. Mutating it between verification and
    /// deserialisation would mean executing a payload that no signature covered.
    /// </para>
    /// <para>
    /// This type deliberately has no dependency on Acumatica or ASP.NET. The adapter assembly builds
    /// one of these from the platform's request object, which keeps the whole authentication surface
    /// unit-testable without an ERP instance.
    /// </para>
    /// </remarks>
    public sealed class WebhookAuthContext
    {
        private static readonly IReadOnlyList<string> NoValues = Array.Empty<string>();

        private readonly Dictionary<string, IReadOnlyList<string>> _headers;

        /// <summary>
        /// Creates a context from multi-valued headers. This is the shape the platform provides and
        /// the one an adapter should use.
        /// </summary>
        /// <param name="body">
        /// Raw request body bytes, exactly as received. Retained by reference, not copied — see the
        /// remarks on this type for the obligation that creates.
        /// </param>
        /// <param name="headers">
        /// Request headers. Matched case-insensitively regardless of the comparer on the dictionary
        /// passed in.
        /// </param>
        /// <param name="method">HTTP method, e.g. "POST". Optional; only needed by templates using <c>{method}</c>.</param>
        /// <param name="path">Request path. Optional; only needed by templates using <c>{path}</c>.</param>
        /// <param name="receivedOn">
        /// When the request arrived. Supplied rather than read from the clock so that replay-window
        /// behaviour is deterministic under test.
        /// </param>
        /// <exception cref="ArgumentNullException"><paramref name="body"/> or <paramref name="headers"/> is null.</exception>
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

        /// <summary>
        /// Creates a context from single-valued headers, for callers that have already flattened
        /// them.
        /// </summary>
        /// <param name="body">Raw request body bytes, exactly as received.</param>
        /// <param name="headers">Request headers, one value each.</param>
        /// <param name="method">HTTP method. Optional.</param>
        /// <param name="path">Request path. Optional.</param>
        /// <param name="receivedOn">When the request arrived.</param>
        /// <exception cref="ArgumentNullException"><paramref name="body"/> or <paramref name="headers"/> is null.</exception>
        public WebhookAuthContext(
            byte[] body,
            IReadOnlyDictionary<string, string> headers,
            string? method,
            string? path,
            DateTimeOffset receivedOn)
            : this(body, Widen(headers), method, path, receivedOn)
        {
        }

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
    }
}
