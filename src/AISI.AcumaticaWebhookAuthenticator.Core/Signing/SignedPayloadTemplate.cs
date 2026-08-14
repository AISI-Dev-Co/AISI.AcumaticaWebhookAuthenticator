// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Diagnostics;

namespace AISI.AcumaticaWebhookAuthenticator.Signing
{
    /// <summary>
    /// Describes the exact byte sequence a sender signs.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the piece that makes the library useful across senders rather than for one sender.
    /// GitHub signs the body alone; Stripe signs <c>{timestamp}.{body}</c>; others prepend the HTTP
    /// method or the request path. Rather than a strategy class per vendor, the convention is a
    /// template string resolved at verification time.
    /// </para>
    /// <para>
    /// Supported tokens: <c>{body}</c>, <c>{timestamp}</c>, <c>{method}</c>, <c>{path}</c> and
    /// <c>{header:Name}</c>. A literal brace is written <c>{{</c> or <c>}}</c>.
    /// </para>
    /// <para>
    /// Resolution produces <em>bytes</em>, not a string. <c>{body}</c> contributes the raw request
    /// bytes verbatim; only the literal segments and the scalar tokens are UTF-8 encoded. Building
    /// the signed payload as a string would force the body through a decode/encode round trip, which
    /// is not lossless for a body carrying a BOM, a non-UTF-8 charset or an invalid byte sequence.
    /// </para>
    /// </remarks>
    public sealed class SignedPayloadTemplate
    {
        private readonly IReadOnlyList<Segment> _segments;

        private SignedPayloadTemplate(string pattern, IReadOnlyList<Segment> segments)
        {
            Pattern = pattern;
            _segments = segments;

            foreach (Segment segment in segments)
            {
                if (segment.Kind == SegmentKind.Timestamp)
                {
                    ReferencesTimestamp = true;
                }
                else if (segment.Kind == SegmentKind.Path)
                {
                    ReferencesPath = true;
                }
            }
        }

        /// <summary>The body alone. The most common convention; GitHub and Shopify both use it.</summary>
        public static SignedPayloadTemplate Body { get; } = Parse("{body}");

        /// <summary>The Stripe convention: the timestamp, a full stop, then the body.</summary>
        public static SignedPayloadTemplate TimestampDotBody { get; } = Parse("{timestamp}.{body}");

        /// <summary>The template string this was parsed from.</summary>
        public string Pattern { get; }

        /// <summary>
        /// Whether the template includes a <c>{timestamp}</c> token, and therefore whether a replay
        /// window over that timestamp would actually be covered by the signature.
        /// </summary>
        public bool ReferencesTimestamp { get; }

        /// <summary>
        /// Whether the template includes a <c>{path}</c> token. A host that cannot supply a request
        /// path — Acumatica's <c>WebhookRequest</c> has no path member — should reject such a
        /// template when the handler is constructed, rather than let every request fail
        /// <c>template_path_unavailable</c> at runtime.
        /// </summary>
        public bool ReferencesPath { get; }

        /// <summary>
        /// Parses a template.
        /// </summary>
        /// <param name="pattern">Template string.</param>
        /// <returns>The parsed template.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="pattern"/> is null.</exception>
        /// <exception cref="FormatException">
        /// The template is malformed or names a token that does not exist. This throws rather than
        /// failing at request time because a bad template is a developer error that should surface
        /// when the handler is constructed, not as a puzzling 401 in production.
        /// </exception>
        public static SignedPayloadTemplate Parse(string pattern)
        {
            if (pattern is null)
            {
                throw new ArgumentNullException(nameof(pattern));
            }

            var segments = new List<Segment>();
            var literal = new StringBuilder();

            for (int i = 0; i < pattern.Length; i++)
            {
                char c = pattern[i];

                if (c == '{' && i + 1 < pattern.Length && pattern[i + 1] == '{')
                {
                    literal.Append('{');
                    i++;
                    continue;
                }

                if (c == '}' && i + 1 < pattern.Length && pattern[i + 1] == '}')
                {
                    literal.Append('}');
                    i++;
                    continue;
                }

                if (c == '}')
                {
                    throw new FormatException(
                        FormattableString.Invariant($"Unbalanced '}}' at position {i} in signed-payload template."));
                }

                if (c != '{')
                {
                    literal.Append(c);
                    continue;
                }

                int close = pattern.IndexOf('}', i + 1);
                if (close < 0)
                {
                    throw new FormatException(
                        FormattableString.Invariant($"Unterminated token starting at position {i} in signed-payload template."));
                }

                if (literal.Length > 0)
                {
                    segments.Add(Segment.ForLiteral(literal.ToString()));
                    literal.Clear();
                }

                segments.Add(ParseToken(pattern.Substring(i + 1, close - i - 1)));
                i = close;
            }

            if (literal.Length > 0)
            {
                segments.Add(Segment.ForLiteral(literal.ToString()));
            }

            return new SignedPayloadTemplate(pattern, segments);
        }

        /// <summary>
        /// Resolves the template against a request.
        /// </summary>
        /// <param name="context">The request being authenticated.</param>
        /// <param name="timestampRaw">
        /// The timestamp exactly as it appeared on the wire, or <see langword="null"/> when the scheme
        /// has no timestamp. The raw form matters: a sender signs the characters it sent, so
        /// re-formatting a parsed timestamp would produce a different signed payload.
        /// </param>
        /// <param name="capturePreview">
        /// Whether to build the human-readable rendering as well. Off by default: the preview decodes
        /// the entire body to a string, which on the verification path is a full extra copy of every
        /// payload allocated for a diagnostic nobody reads. Only
        /// <see cref="Diagnostics.WebhookSignatureTester"/> asks for it.
        /// </param>
        /// <returns>The resolution, successful or otherwise.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="context"/> is null.</exception>
        public TemplateResolution Resolve(WebhookAuthContext context, string? timestampRaw, bool capturePreview = false)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // The single-{body} template is the overwhelmingly common case (GitHub, Shopify) and
            // needs no composition at all: the signed payload IS the request body. Handing the
            // buffer back avoids copying every payload on the hot path - which the deliberate
            // refusal to defensively copy WebhookAuthContext.Body would otherwise be undone by.
            if (_segments.Count == 1 && _segments[0].Kind == SegmentKind.Body)
            {
                return TemplateResolution.Succeeded(
                    context.Body,
                    capturePreview ? Encoding.UTF8.GetString(context.Body) : string.Empty);
            }

            StringBuilder? preview = capturePreview ? new StringBuilder() : null;

            using (var buffer = new MemoryStream(context.Body.Length + Pattern.Length + 32))
            {
                foreach (Segment segment in _segments)
                {
                    if (segment.Kind == SegmentKind.Body)
                    {
                        buffer.Write(context.Body, 0, context.Body.Length);

                        // Lossy by design, and only ever for display: the digest is computed from
                        // the bytes written above, never from this string.
                        preview?.Append(Encoding.UTF8.GetString(context.Body));
                        continue;
                    }

                    if (!TryResolveScalar(segment, context, timestampRaw, out string text, out string failureCode))
                    {
                        return TemplateResolution.Failed(failureCode);
                    }

                    byte[] encoded = Encoding.UTF8.GetBytes(text);
                    buffer.Write(encoded, 0, encoded.Length);
                    preview?.Append(text);
                }

                return TemplateResolution.Succeeded(buffer.ToArray(), preview?.ToString() ?? string.Empty);
            }
        }

        private static bool TryResolveScalar(
            Segment segment,
            WebhookAuthContext context,
            string? timestampRaw,
            out string text,
            out string failureCode)
        {
            failureCode = string.Empty;

            switch (segment.Kind)
            {
                case SegmentKind.Literal:
                    text = segment.Value;
                    return true;

                case SegmentKind.Timestamp:
                    if (timestampRaw is null)
                    {
                        text = string.Empty;
                        failureCode = AuthFailureCode.TimestampMissing;
                        return false;
                    }

                    text = timestampRaw;
                    return true;

                case SegmentKind.Method:
                    if (context.Method is null)
                    {
                        text = string.Empty;
                        failureCode = AuthFailureCode.TemplateMethodUnavailable;
                        return false;
                    }

                    text = context.Method;
                    return true;

                case SegmentKind.Path:
                    if (context.Path is null)
                    {
                        text = string.Empty;
                        failureCode = AuthFailureCode.TemplatePathUnavailable;
                        return false;
                    }

                    text = context.Path;
                    return true;

                case SegmentKind.Header:
                    // A template naming a header the sender did not send fails resolution outright
                    // rather than substituting an empty string. Both end in a 401, but this way the
                    // trace says which header was missing instead of reporting an opaque mismatch.
                    if (!context.TryGetHeader(segment.Value, out string headerValue))
                    {
                        text = string.Empty;
                        failureCode = AuthFailureCode.TemplateHeaderMissing;
                        return false;
                    }

                    text = headerValue;
                    return true;

                default:
                    text = string.Empty;
                    failureCode = AuthFailureCode.TemplateInvalid;
                    return false;
            }
        }

        private static Segment ParseToken(string token)
        {
            if (token.StartsWith("header:", StringComparison.OrdinalIgnoreCase))
            {
                string headerName = token.Substring("header:".Length).Trim();
                if (headerName.Length == 0)
                {
                    throw new FormatException("The {header:Name} token requires a header name.");
                }

                return Segment.ForHeader(headerName);
            }

            switch (token.Trim().ToLowerInvariant())
            {
                case "body":
                    return Segment.ForKind(SegmentKind.Body);
                case "timestamp":
                    return Segment.ForKind(SegmentKind.Timestamp);
                case "method":
                    return Segment.ForKind(SegmentKind.Method);
                case "path":
                    return Segment.ForKind(SegmentKind.Path);
                default:
                    throw new FormatException(
                        string.Format(
                            CultureInfo.InvariantCulture,
                            "Unknown token '{{{0}}}' in signed-payload template. Supported tokens are {{body}}, {{timestamp}}, {{method}}, {{path}} and {{header:Name}}.",
                            token));
            }
        }

        private enum SegmentKind
        {
            Literal,
            Body,
            Timestamp,
            Method,
            Path,
            Header,
        }

        private readonly struct Segment
        {
            private Segment(SegmentKind kind, string value)
            {
                Kind = kind;
                Value = value;
            }

            public SegmentKind Kind { get; }

            public string Value { get; }

            public static Segment ForLiteral(string value) => new Segment(SegmentKind.Literal, value);

            public static Segment ForHeader(string name) => new Segment(SegmentKind.Header, name);

            public static Segment ForKind(SegmentKind kind) => new Segment(kind, string.Empty);
        }
    }
}
