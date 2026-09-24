// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Text;
using AISI.AcumaticaWebhookAuthenticator.Signing;

namespace AISI.AcumaticaWebhookAuthenticator.Configuration
{
    /// <summary>Signing secret, optionally with a second key accepted until a rotation expiry.</summary>
    public sealed class WebhookSecret
    {
        #region Construction and state
        /// <summary>The prefix Standard Webhooks senders put in front of the base64 key.</summary>
        public const string StandardWebhooksPrefix = "whsec_";

        private readonly byte[] _current;
        private readonly byte[]? _rotating;
        private readonly DateTimeOffset? _rotatingExpiresOn;

        private WebhookSecret(byte[] current, byte[]? rotating, DateTimeOffset? rotatingExpiresOn)
        {
            _current = current;
            _rotating = rotating;
            _rotatingExpiresOn = rotatingExpiresOn;
        }
        #endregion

        #region Creation
        /// <summary>Creates a secret from raw key bytes, which are copied.</summary>
        /// <param name="current">The active secret.</param>
        /// <returns>The secret.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="current"/> is null.</exception>
        /// <exception cref="ArgumentException"><paramref name="current"/> is empty.</exception>
        public static WebhookSecret FromBytes(byte[] current) =>
            new WebhookSecret(CopyKey(current, nameof(current)), null, null);

        /// <summary>Creates a secret from its UTF-8 text form, as pasted from most sender dashboards.</summary>
        /// <param name="current">The active secret.</param>
        /// <returns>The secret.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="current"/> is null.</exception>
        /// <exception cref="FormatException"><paramref name="current"/> is empty.</exception>
        public static WebhookSecret FromUtf8(string current) => Parse(current, SecretEncoding.Utf8);

        /// <summary>Creates a secret from its text form under <paramref name="encoding"/>.</summary>
        /// <param name="current">The active secret's text form.</param>
        /// <param name="encoding">How the text maps to key bytes.</param>
        /// <returns>The secret.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="current"/> is null.</exception>
        /// <exception cref="FormatException">
        /// The text is not valid under <paramref name="encoding"/>, or decodes to an empty key.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="encoding"/> is undefined.</exception>
        public static WebhookSecret Parse(string current, SecretEncoding encoding) =>
            new WebhookSecret(Decode(current, encoding, nameof(current)), null, null);
        #endregion

        #region Rotation
        /// <summary>Returns a copy of this secret that also accepts <paramref name="rotating"/> until <paramref name="expiresOn"/>.</summary>
        /// <param name="rotating">The other secret accepted during the overlap. Copied.</param>
        /// <param name="expiresOn">When the overlap ends, so a forgotten rotation closes itself.</param>
        /// <returns>A new secret carrying the overlap.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="rotating"/> is null.</exception>
        /// <exception cref="ArgumentException"><paramref name="rotating"/> is empty.</exception>
        public WebhookSecret WithRotating(byte[] rotating, DateTimeOffset expiresOn) =>
            new WebhookSecret(_current, CopyKey(rotating, nameof(rotating)), expiresOn);

        /// <summary>Returns a copy of this secret with a rotating counterpart supplied as UTF-8 text.</summary>
        /// <param name="rotating">The other secret accepted during the overlap.</param>
        /// <param name="expiresOn">When the overlap ends.</param>
        /// <returns>A new secret carrying the overlap.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="rotating"/> is null.</exception>
        /// <exception cref="FormatException"><paramref name="rotating"/> is empty.</exception>
        public WebhookSecret WithRotatingUtf8(string rotating, DateTimeOffset expiresOn) =>
            WithRotating(rotating, SecretEncoding.Utf8, expiresOn);

        /// <summary>Returns a copy of this secret with a rotating counterpart in its text form under <paramref name="encoding"/>.</summary>
        /// <param name="rotating">The other secret accepted during the overlap.</param>
        /// <param name="encoding">How the text maps to key bytes.</param>
        /// <param name="expiresOn">When the overlap ends.</param>
        /// <returns>A new secret carrying the overlap.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="rotating"/> is null.</exception>
        /// <exception cref="FormatException">
        /// The text is not valid under <paramref name="encoding"/>, or decodes to an empty key.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="encoding"/> is undefined.</exception>
        public WebhookSecret WithRotating(string rotating, SecretEncoding encoding, DateTimeOffset expiresOn) =>
            new WebhookSecret(_current, Decode(rotating, encoding, nameof(rotating)), expiresOn);
        #endregion

        #region Verification
        /// <summary>Whether <paramref name="providedDigest"/> signs <paramref name="message"/> under any secret live at <paramref name="asOf"/>.</summary>
        /// <param name="algorithm">Hash algorithm.</param>
        /// <param name="message">The exact bytes the sender signed.</param>
        /// <param name="providedDigest">The digest supplied on the request.</param>
        /// <param name="asOf">The instant to evaluate the rotation window against.</param>
        /// <returns><see langword="true"/> when the signature is valid.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="message"/> is null.</exception>
        public bool Matches(HmacAlgorithm algorithm, byte[] message, byte[]? providedDigest, DateTimeOffset asOf) =>
            MatchesAny(algorithm, message, new[] { providedDigest }, asOf);

        /// <summary>Whether any of <paramref name="providedDigests"/> signs <paramref name="message"/> under any secret live at <paramref name="asOf"/>.</summary>
        /// <param name="algorithm">Hash algorithm.</param>
        /// <param name="message">The exact bytes the sender signed.</param>
        /// <param name="providedDigests">Every digest offered on the request.</param>
        /// <param name="asOf">The instant to evaluate the rotation window against.</param>
        /// <returns><see langword="true"/> when any pairing is valid.</returns>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="message"/> or <paramref name="providedDigests"/> is null.
        /// </exception>
        public bool MatchesAny(
            HmacAlgorithm algorithm,
            byte[] message,
            IReadOnlyList<byte[]?> providedDigests,
            DateTimeOffset asOf)
        {
            if (message is null)
            {
                throw new ArgumentNullException(nameof(message));
            }

            if (providedDigests is null)
            {
                throw new ArgumentNullException(nameof(providedDigests));
            }

            bool matched = false;

            // Not short-circuited: an early return would time-leak which secret (current or rotating) matched.
            foreach (byte[] key in LiveKeys(asOf))
            {
                byte[] expected = HmacComputer.Compute(algorithm, key, message);

                foreach (byte[]? provided in providedDigests)
                {
                    matched |= FixedTimeComparer.AreEqual(expected, provided);
                }
            }

            return matched;
        }

        /// <summary>Whether <paramref name="provided"/> equals any secret live at <paramref name="asOf"/>, for schemes that send the secret itself.</summary>
        /// <param name="provided">The credential supplied on the request. Null never matches.</param>
        /// <param name="asOf">The instant to evaluate the rotation window against.</param>
        /// <returns><see langword="true"/> when the credential matches.</returns>
        public bool MatchesValue(byte[]? provided, DateTimeOffset asOf)
        {
            bool matched = false;

            // Not short-circuited, for the same reason as MatchesAny.
            foreach (byte[] key in LiveKeys(asOf))
            {
                matched |= FixedTimeComparer.AreEqual(key, provided);
            }

            return matched;
        }
        #endregion

        #region Diagnostics
        /// <summary>The digests each live secret would produce. For administrators only; never expose over HTTP.</summary>
        /// <param name="algorithm">Hash algorithm.</param>
        /// <param name="message">The bytes to sign.</param>
        /// <param name="asOf">The instant to evaluate the rotation window against.</param>
        /// <returns>One digest per live secret: the current one first, then the rotating one.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="message"/> is null.</exception>
        public IReadOnlyList<byte[]> ComputeDiagnosticDigests(
            HmacAlgorithm algorithm,
            byte[] message,
            DateTimeOffset asOf)
        {
            if (message is null)
            {
                throw new ArgumentNullException(nameof(message));
            }

            var digests = new List<byte[]>(2);

            foreach (byte[] key in LiveKeys(asOf))
            {
                digests.Add(HmacComputer.Compute(algorithm, key, message));
            }

            return digests;
        }
        #endregion

        #region Internals
        private static byte[] CopyKey(byte[] source, string parameterName)
        {
            if (source is null)
            {
                throw new ArgumentNullException(parameterName);
            }

            if (source.Length == 0)
            {
                throw new ArgumentException("A secret cannot be empty.", parameterName);
            }

            return (byte[])source.Clone();
        }

        private static byte[] Decode(string text, SecretEncoding encoding, string parameterName)
        {
            if (text is null)
            {
                throw new ArgumentNullException(parameterName);
            }

            byte[] key;

            switch (encoding)
            {
                case SecretEncoding.Utf8:
                    key = Encoding.UTF8.GetBytes(text);
                    break;

                case SecretEncoding.Base64:
                    key = DecodeOrThrow(text, SignatureEncoding.Base64, "base64");
                    break;

                case SecretEncoding.Hex:
                    key = DecodeOrThrow(text, SignatureEncoding.Hex, "hexadecimal");
                    break;

                case SecretEncoding.StandardWebhooks:
                    string encoded = text.StartsWith(StandardWebhooksPrefix, StringComparison.Ordinal)
                        ? text.Substring(StandardWebhooksPrefix.Length)
                        : text;
                    key = DecodeOrThrow(encoded, SignatureEncoding.Base64, "a Standard Webhooks (whsec_) secret");
                    break;

                default:
                    throw new ArgumentOutOfRangeException(nameof(encoding), encoding, "Unknown secret encoding.");
            }

            // Anyone can compute an HMAC under an empty key.
            if (key.Length == 0)
            {
                throw new FormatException("A secret cannot be empty.");
            }

            return key;
        }

        private static byte[] DecodeOrThrow(string text, SignatureEncoding encoding, string description)
        {
            if (!SignatureCodec.TryDecode(text, encoding, out byte[] bytes))
            {
                throw new FormatException("The secret is not valid " + description + ".");
            }

            return bytes;
        }

        private IEnumerable<byte[]> LiveKeys(DateTimeOffset asOf)
        {
            yield return _current;

            if (_rotating is object && _rotatingExpiresOn is object && asOf <= _rotatingExpiresOn.Value)
            {
                yield return _rotating;
            }
        }
        #endregion
    }
}
