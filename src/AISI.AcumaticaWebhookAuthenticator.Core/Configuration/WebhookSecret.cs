// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Text;
using AISI.AcumaticaWebhookAuthenticator.Signing;

namespace AISI.AcumaticaWebhookAuthenticator.Configuration
{
    /// <summary>
    /// A signing secret, optionally with a second secret valid during a rotation overlap.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Rotation is not an edge case. A sender rotating its signing secret emits requests signed with
    /// either the old or the new one for the length of the overlap window, and a verifier that knows
    /// only one of them drops roughly half the traffic for the duration.
    /// </para>
    /// <para>
    /// Key material never leaves this type. Verification happens in <see cref="Matches"/> rather
    /// than by handing the caller the bytes, so there is no reference an unrelated component can
    /// hold on to or mutate, and every candidate is evaluated even after one has matched — an early
    /// return would leak through timing which of the two secrets is live.
    /// </para>
    /// </remarks>
    public sealed class WebhookSecret
    {
        private readonly byte[] _current;
        private readonly byte[]? _rotating;
        private readonly DateTimeOffset? _rotatingExpiresOn;

        private WebhookSecret(byte[] current, byte[]? rotating, DateTimeOffset? rotatingExpiresOn)
        {
            _current = current;
            _rotating = rotating;
            _rotatingExpiresOn = rotatingExpiresOn;
        }

        /// <summary>
        /// Creates a secret from raw key bytes. The array is copied, so later mutation by the caller
        /// cannot change what this secret verifies against.
        /// </summary>
        /// <param name="current">The active secret.</param>
        /// <returns>The secret.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="current"/> is null.</exception>
        public static WebhookSecret FromBytes(byte[] current)
        {
            if (current is null)
            {
                throw new ArgumentNullException(nameof(current));
            }

            return new WebhookSecret(Copy(current), null, null);
        }

        /// <summary>
        /// Creates a secret from its UTF-8 text form. This is what most senders mean by a
        /// "signing secret" or "webhook secret" pasted from a dashboard.
        /// </summary>
        /// <param name="current">The active secret.</param>
        /// <returns>The secret.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="current"/> is null.</exception>
        public static WebhookSecret FromUtf8(string current)
        {
            if (current is null)
            {
                throw new ArgumentNullException(nameof(current));
            }

            return new WebhookSecret(Encoding.UTF8.GetBytes(current), null, null);
        }

        /// <summary>
        /// Creates a secret from a hex-encoded key.
        /// </summary>
        /// <param name="current">Hex-encoded secret.</param>
        /// <returns>The secret.</returns>
        /// <exception cref="FormatException">The value is not valid hex.</exception>
        public static WebhookSecret FromHex(string current)
        {
            if (!SignatureCodec.TryDecode(current, SignatureEncoding.Hex, out byte[] bytes))
            {
                throw new FormatException("The secret is not valid hexadecimal.");
            }

            return new WebhookSecret(bytes, null, null);
        }

        /// <summary>
        /// Creates a secret from a base64-encoded key.
        /// </summary>
        /// <param name="current">Base64-encoded secret.</param>
        /// <returns>The secret.</returns>
        /// <exception cref="FormatException">The value is not valid base64.</exception>
        public static WebhookSecret FromBase64(string current)
        {
            if (!SignatureCodec.TryDecode(current, SignatureEncoding.Base64, out byte[] bytes))
            {
                throw new FormatException("The secret is not valid base64.");
            }

            return new WebhookSecret(bytes, null, null);
        }

        /// <summary>
        /// Returns a copy of this secret with a rotating counterpart valid until an expiry.
        /// </summary>
        /// <param name="rotating">The other secret accepted during the overlap.</param>
        /// <param name="expiresOn">
        /// When the overlap ends. After this instant the rotating secret is no longer accepted, so a
        /// forgotten rotation closes itself rather than leaving a retired secret live indefinitely.
        /// </param>
        /// <returns>A new secret carrying the overlap.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="rotating"/> is null.</exception>
        public WebhookSecret WithRotating(byte[] rotating, DateTimeOffset expiresOn)
        {
            if (rotating is null)
            {
                throw new ArgumentNullException(nameof(rotating));
            }

            return new WebhookSecret(_current, Copy(rotating), expiresOn);
        }

        /// <summary>
        /// Returns a copy of this secret with a rotating counterpart supplied as UTF-8 text.
        /// </summary>
        /// <param name="rotating">The other secret accepted during the overlap.</param>
        /// <param name="expiresOn">When the overlap ends.</param>
        /// <returns>A new secret carrying the overlap.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="rotating"/> is null.</exception>
        public WebhookSecret WithRotatingUtf8(string rotating, DateTimeOffset expiresOn)
        {
            if (rotating is null)
            {
                throw new ArgumentNullException(nameof(rotating));
            }

            return new WebhookSecret(_current, Encoding.UTF8.GetBytes(rotating), expiresOn);
        }

        /// <summary>
        /// Whether <paramref name="providedDigest"/> is a valid signature of
        /// <paramref name="message"/> under any secret live at <paramref name="asOf"/>.
        /// </summary>
        /// <param name="algorithm">Hash algorithm.</param>
        /// <param name="message">The exact bytes the sender signed.</param>
        /// <param name="providedDigest">The digest supplied on the request.</param>
        /// <param name="asOf">The instant to evaluate the rotation window against.</param>
        /// <returns><see langword="true"/> when the signature is valid.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="message"/> is null.</exception>
        public bool Matches(HmacAlgorithm algorithm, byte[] message, byte[]? providedDigest, DateTimeOffset asOf) =>
            MatchesAny(algorithm, message, new[] { providedDigest }, asOf);

        /// <summary>
        /// Whether any of <paramref name="providedDigests"/> is a valid signature of
        /// <paramref name="message"/> under any secret live at <paramref name="asOf"/>.
        /// </summary>
        /// <param name="algorithm">Hash algorithm.</param>
        /// <param name="message">The exact bytes the sender signed.</param>
        /// <param name="providedDigests">Every digest offered on the request.</param>
        /// <param name="asOf">The instant to evaluate the rotation window against.</param>
        /// <returns><see langword="true"/> when any pairing is valid.</returns>
        /// <remarks>
        /// Takes the whole candidate set at once so each key is hashed exactly once. Verifying one
        /// candidate at a time recomputed the same digest per candidate — four HMACs for a Stripe
        /// request carrying two <c>v1</c> elements during a rotation overlap — and made the work
        /// done visible in the candidate count rather than fixed by configuration.
        /// </remarks>
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

            // Deliberately not short-circuited, in either loop. Returning on the first hit would
            // make a request signed with the current secret measurably faster than one signed with
            // the rotating secret, which tells an observer which is which.
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

        /// <summary>
        /// Whether <paramref name="provided"/> is byte-for-byte equal to any secret live at
        /// <paramref name="asOf"/> — direct credential comparison, no hashing, for the schemes
        /// where the caller presents the secret itself (<c>SECRET</c>, <c>BASIC</c>).
        /// </summary>
        /// <param name="provided">The credential supplied on the request. Null never matches.</param>
        /// <param name="asOf">The instant to evaluate the rotation window against.</param>
        /// <remarks>
        /// Fixed-time per candidate and not short-circuited across the current and rotating
        /// secrets, for the same reason as <see cref="MatchesAny"/>. Per the
        /// <see cref="Signing.FixedTimeComparer"/> contract, lengths are not secret.
        /// </remarks>
        public bool MatchesValue(byte[]? provided, DateTimeOffset asOf)
        {
            bool matched = false;

            foreach (byte[] key in LiveKeys(asOf))
            {
                matched |= FixedTimeComparer.AreEqual(key, provided);
            }

            return matched;
        }

        /// <summary>
        /// Computes the digests this secret would produce, for display by
        /// <see cref="Diagnostics.WebhookSignatureTester"/>.
        /// </summary>
        /// <param name="algorithm">Hash algorithm.</param>
        /// <param name="message">The bytes to sign.</param>
        /// <param name="asOf">The instant to evaluate the rotation window against.</param>
        /// <returns>One digest per live secret: the current one first, then the rotating one.</returns>
        /// <remarks>
        /// This is the only member that yields anything derived from the key to a caller, and it
        /// exists solely so an administrator with access to the secret can see why a signature did
        /// not match. Never expose its output over HTTP.
        /// </remarks>
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

        private static byte[] Copy(byte[] source)
        {
            var copy = new byte[source.Length];
            Buffer.BlockCopy(source, 0, copy, 0, source.Length);
            return copy;
        }

        private IEnumerable<byte[]> LiveKeys(DateTimeOffset asOf)
        {
            yield return _current;

            if (_rotating is object && _rotatingExpiresOn is object && asOf <= _rotatingExpiresOn.Value)
            {
                yield return _rotating;
            }
        }
    }
}
