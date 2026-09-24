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
    /// <summary>Byte sequence the sender signs. Tokens: <c>{body}</c>, <c>{timestamp}</c>, <c>{method}</c>, <c>{path}</c>, <c>{header:Name}</c>.</summary>
    public sealed class SignedPayloadTemplate
    {
        #region Construction and state
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
        #endregion

        #region Presets and properties
        /// <summary>The body alone. The most common convention; GitHub and Shopify both use it.</summary>
        public static SignedPayloadTemplate Body { get; } = Parse("{body}");

        /// <summary>The Stripe convention: the timestamp, a full stop, then the body.</summary>
        public static SignedPayloadTemplate TimestampDotBody { get; } = Parse("{timestamp}.{body}");

        /// <summary>The template string this was parsed from.</summary>
        public string Pattern { get; }

        /// <summary>Whether the template includes a <c>{timestamp}</c> token, so a replay window would be signed.</summary>
        public bool ReferencesTimestamp { get; }

        /// <summary>Whether the template includes a <c>{path}</c> token, which a host with no request path cannot supply.</summary>
        public bool ReferencesPath { get; }
        #endregion

        #region Parsing
        /// <summary>Parses a template.</summary>
        /// <param name="pattern">Template string. <c>{{</c> and <c>}}</c> are literal braces.</param>
        /// <returns>The parsed template.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="pattern"/> is null.</exception>
        /// <exception cref="FormatException">The template is malformed or names a token that does not exist.</exception>
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
                    segments.Add(new Segment(SegmentKind.Literal, literal.ToString()));
                    literal.Clear();
                }

                segments.Add(ParseToken(pattern.Substring(i + 1, close - i - 1)));
                i = close;
            }

            if (literal.Length > 0)
            {
                segments.Add(new Segment(SegmentKind.Literal, literal.ToString()));
            }

            return new SignedPayloadTemplate(pattern, segments);
        }
        #endregion

        #region Resolution
        /// <summary>Resolves the template against a request.</summary>
        /// <param name="context">The request being authenticated.</param>
        /// <param name="timestampRaw">
        /// The timestamp exactly as sent, or <see langword="null"/> when the scheme has none. Never
        /// re-format it: the sender signed the characters it sent.
        /// </param>
        /// <param name="capturePreview">Whether to build <see cref="TemplateResolution.Preview"/> too; a full body copy, so off on the request path.</param>
        /// <returns>The resolution, successful or otherwise.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="context"/> is null.</exception>
        public TemplateResolution Resolve(WebhookAuthContext context, string? timestampRaw, bool capturePreview = false)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // A bare {body} aliases the request buffer rather than copying every payload on the hot path.
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
                        // The raw bytes are signed; the lossy UTF-8 decode is only for display.
                        buffer.Write(context.Body, 0, context.Body.Length);
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
        #endregion

        #region Internals
        private static bool TryResolveScalar(
            Segment segment,
            WebhookAuthContext context,
            string? timestampRaw,
            out string text,
            out string failureCode)
        {
            text = string.Empty;
            failureCode = string.Empty;

            switch (segment.Kind)
            {
                case SegmentKind.Literal:
                    text = segment.Value;
                    return true;

                case SegmentKind.Timestamp:
                    if (timestampRaw is null)
                    {
                        failureCode = AuthFailureCode.TimestampMissing;
                        return false;
                    }

                    text = timestampRaw;
                    return true;

                case SegmentKind.Method:
                    if (context.Method is null)
                    {
                        failureCode = AuthFailureCode.TemplateMethodUnavailable;
                        return false;
                    }

                    text = context.Method;
                    return true;

                case SegmentKind.Path:
                    if (context.Path is null)
                    {
                        failureCode = AuthFailureCode.TemplatePathUnavailable;
                        return false;
                    }

                    text = context.Path;
                    return true;

                case SegmentKind.Header:
                    // Fail rather than substitute "" so the trace names the missing header.
                    if (!context.TryGetHeader(segment.Value, out string headerValue))
                    {
                        failureCode = AuthFailureCode.TemplateHeaderMissing;
                        return false;
                    }

                    text = headerValue;
                    return true;

                default:
                    throw new InvalidOperationException(
                        FormattableString.Invariant($"Segment kind '{segment.Kind}' is not a scalar."));
            }
        }

        private static Segment ParseToken(string rawToken)
        {
            string token = rawToken.Trim();

            if (token.StartsWith("header:", StringComparison.OrdinalIgnoreCase))
            {
                string headerName = token.Substring("header:".Length).Trim();
                if (headerName.Length == 0)
                {
                    throw new FormatException("The {header:Name} token requires a header name.");
                }

                return new Segment(SegmentKind.Header, headerName);
            }

            switch (token.ToLowerInvariant())
            {
                case "body":
                    return new Segment(SegmentKind.Body, string.Empty);
                case "timestamp":
                    return new Segment(SegmentKind.Timestamp, string.Empty);
                case "method":
                    return new Segment(SegmentKind.Method, string.Empty);
                case "path":
                    return new Segment(SegmentKind.Path, string.Empty);
                default:
                    throw new FormatException(
                        string.Format(
                            CultureInfo.InvariantCulture,
                            "Unknown token '{{{0}}}' in signed-payload template. Supported tokens are {{body}}, {{timestamp}}, {{method}}, {{path}} and {{header:Name}}.",
                            rawToken));
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
            public Segment(SegmentKind kind, string value)
            {
                Kind = kind;
                Value = value;
            }

            public SegmentKind Kind { get; }

            public string Value { get; }
        }
        #endregion
    }
}
