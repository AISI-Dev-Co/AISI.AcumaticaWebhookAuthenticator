// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;

namespace AISI.AcumaticaWebhookAuthenticator.Configuration
{
    /// <summary>
    /// How to get the signature out of a header value.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A header name plus an optional prefix covers GitHub (<c>sha256=…</c>) and Shopify (bare
    /// base64), but not Stripe, whose header is a compound list:
    /// <c>Stripe-Signature: t=1614556800,v1=5257a8…,v0=6ffbb5…</c>. Extracting a named element from
    /// a delimited list is therefore a first-class mode rather than something a consumer is left to
    /// pre-process.
    /// </para>
    /// <para>
    /// Element extraction returns <em>every</em> match, not the first. Stripe emits one <c>v1</c>
    /// per active endpoint secret, so during a rotation on their side the correct signature may not
    /// be the first one in the header.
    /// </para>
    /// </remarks>
    public sealed class SignatureExtraction
    {
        private readonly string? _elementKey;
        private readonly char _pairSeparator;
        private readonly char _keyValueSeparator;

        private SignatureExtraction(string? elementKey, char pairSeparator, char keyValueSeparator)
        {
            _elementKey = elementKey;
            _pairSeparator = pairSeparator;
            _keyValueSeparator = keyValueSeparator;
        }

        /// <summary>The whole header value is the signature. The common case.</summary>
        public static SignatureExtraction Whole { get; } = new SignatureExtraction(null, ',', '=');

        /// <summary>
        /// The signature is the value of a named element in a delimited key/value list.
        /// </summary>
        /// <param name="elementKey">Element name, e.g. "v1" for Stripe.</param>
        /// <param name="pairSeparator">Separator between elements. Defaults to ','.</param>
        /// <param name="keyValueSeparator">Separator between an element's name and value. Defaults to '='.</param>
        /// <returns>The extraction mode.</returns>
        /// <exception cref="ArgumentException"><paramref name="elementKey"/> is null or blank.</exception>
        public static SignatureExtraction KeyValueElement(
            string elementKey,
            char pairSeparator = ',',
            char keyValueSeparator = '=')
        {
            if (string.IsNullOrWhiteSpace(elementKey))
            {
                throw new ArgumentException("An element key is required.", nameof(elementKey));
            }

            return new SignatureExtraction(elementKey, pairSeparator, keyValueSeparator);
        }

        /// <summary>
        /// Pulls candidate signature values out of a header value.
        /// </summary>
        /// <param name="headerValue">The raw header value.</param>
        /// <returns>Zero or more candidate signatures, in the order they appeared.</returns>
        public IReadOnlyList<string> Extract(string? headerValue)
        {
            if (string.IsNullOrEmpty(headerValue))
            {
                return Array.Empty<string>();
            }

            if (_elementKey is null)
            {
                return new[] { headerValue!.Trim() };
            }

            var matches = new List<string>();

            foreach (string pair in headerValue!.Split(_pairSeparator))
            {
                int split = pair.IndexOf(_keyValueSeparator);
                if (split <= 0)
                {
                    continue;
                }

                string key = pair.Substring(0, split).Trim();
                if (!string.Equals(key, _elementKey, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                matches.Add(pair.Substring(split + 1).Trim());
            }

            return matches;
        }
    }
}
