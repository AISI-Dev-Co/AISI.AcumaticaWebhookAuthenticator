// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;

namespace AISI.AcumaticaWebhookAuthenticator.Configuration
{
    /// <summary>How to get the signature out of a header value: the whole value, or a named element such as Stripe's <c>v1=</c>.</summary>
    public sealed class SignatureExtraction
    {
        #region Construction and state
        private readonly string? _elementKey;
        private readonly char _pairSeparator;
        private readonly char _keyValueSeparator;

        private SignatureExtraction(string? elementKey, char pairSeparator, char keyValueSeparator)
        {
            _elementKey = elementKey;
            _pairSeparator = pairSeparator;
            _keyValueSeparator = keyValueSeparator;
        }
        #endregion

        #region Factories
        /// <summary>The whole header value is the signature. The common case.</summary>
        public static SignatureExtraction Whole { get; } = new SignatureExtraction(null, ',', '=');

        /// <summary>The signature is the value of a named element in a delimited key/value list.</summary>
        /// <param name="elementKey">Element name, e.g. "v1" for Stripe.</param>
        /// <param name="pairSeparator">Separator between elements. Defaults to ','.</param>
        /// <param name="keyValueSeparator">Separator between an element's name and value. Defaults to '='.</param>
        /// <returns>The extraction mode.</returns>
        /// <exception cref="ArgumentException">
        /// <paramref name="elementKey"/> is null or blank, or the two separators are equal.
        /// </exception>
        public static SignatureExtraction KeyValueElement(
            string elementKey,
            char pairSeparator = ',',
            char keyValueSeparator = '=')
        {
            if (string.IsNullOrWhiteSpace(elementKey))
            {
                throw new ArgumentException("An element key is required.", nameof(elementKey));
            }

            if (pairSeparator == keyValueSeparator)
            {
                throw new ArgumentException(
                    "The pair and key/value separators must differ; otherwise no element can ever match.",
                    nameof(keyValueSeparator));
            }

            return new SignatureExtraction(elementKey, pairSeparator, keyValueSeparator);
        }
        #endregion

        #region Extraction
        /// <summary>Pulls candidate signatures out of every value of a repeated header, each value independently.</summary>
        /// <param name="headerValues">The raw header values, in the order they arrived.</param>
        /// <returns>Zero or more candidate signatures.</returns>
        public IReadOnlyList<string> Extract(IReadOnlyList<string>? headerValues)
        {
            if (headerValues is null || headerValues.Count == 0)
            {
                return Array.Empty<string>();
            }

            if (headerValues.Count == 1)
            {
                return Extract(headerValues[0]);
            }

            var all = new List<string>();
            foreach (string headerValue in headerValues)
            {
                all.AddRange(Extract(headerValue));
            }

            return all;
        }

        /// <summary>Pulls every candidate signature out of a single header value; Stripe sends one <c>v1</c> per active secret.</summary>
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
                // Split even whole values, as intermediaries may fold repeats; hex and base64 contain no comma.
                var whole = new List<string>();

                foreach (string part in headerValue!.Split(','))
                {
                    string trimmed = part.Trim();
                    if (trimmed.Length > 0)
                    {
                        whole.Add(trimmed);
                    }
                }

                return whole;
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
        #endregion
    }
}
