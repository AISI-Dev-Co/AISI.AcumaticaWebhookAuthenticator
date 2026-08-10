// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Globalization;
using System.Text;

namespace AISI.AcumaticaWebhookAuthenticator.Signing
{
    /// <summary>
    /// Wire encoding a sender uses to represent a signature digest in a header value.
    /// </summary>
    public enum SignatureEncoding
    {
        /// <summary>Lowercase hexadecimal. Used by GitHub and Stripe.</summary>
        Hex = 0,

        /// <summary>Standard base64 with padding. Used by Shopify.</summary>
        Base64 = 1,
    }

    /// <summary>
    /// Encodes and decodes signature digests.
    /// </summary>
    /// <remarks>
    /// Decoding is deliberately not constant-time. The value being decoded is the signature supplied
    /// by the caller, which is attacker-controlled and public; only the comparison against the
    /// computed digest needs timing protection. See <see cref="FixedTimeComparer"/>.
    /// </remarks>
    public static class SignatureCodec
    {
        /// <summary>
        /// Renders a digest in the given wire encoding.
        /// </summary>
        /// <param name="digest">Raw digest bytes.</param>
        /// <param name="encoding">Target wire encoding.</param>
        /// <returns>The encoded signature.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="digest"/> is null.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="encoding"/> is not a known value.</exception>
        public static string Encode(byte[] digest, SignatureEncoding encoding)
        {
            if (digest is null)
            {
                throw new ArgumentNullException(nameof(digest));
            }

            switch (encoding)
            {
                case SignatureEncoding.Hex:
                    var builder = new StringBuilder(digest.Length * 2);
                    foreach (byte b in digest)
                    {
                        builder.Append(b.ToString("x2", CultureInfo.InvariantCulture));
                    }

                    return builder.ToString();

                case SignatureEncoding.Base64:
                    return Convert.ToBase64String(digest);

                default:
                    throw new ArgumentOutOfRangeException(nameof(encoding), encoding, "Unknown signature encoding.");
            }
        }

        /// <summary>
        /// Attempts to decode a signature from its wire encoding.
        /// </summary>
        /// <param name="value">Encoded signature, as it appeared in the header.</param>
        /// <param name="encoding">Wire encoding to decode from.</param>
        /// <param name="digest">Decoded digest bytes when decoding succeeds.</param>
        /// <returns>
        /// <see langword="false"/> when the value is absent or malformed. A malformed signature is
        /// never an exception: it is an authentication failure like any other, and throwing here
        /// would turn a hostile request into a 500.
        /// </returns>
        public static bool TryDecode(string? value, SignatureEncoding encoding, out byte[] digest)
        {
            digest = Array.Empty<byte>();

            if (string.IsNullOrEmpty(value))
            {
                return false;
            }

            switch (encoding)
            {
                case SignatureEncoding.Hex:
                    return TryDecodeHex(value!, out digest);

                case SignatureEncoding.Base64:
                    try
                    {
                        digest = Convert.FromBase64String(value!);
                        return true;
                    }
                    catch (FormatException)
                    {
                        return false;
                    }

                default:
                    return false;
            }
        }

        private static bool TryDecodeHex(string value, out byte[] digest)
        {
            digest = Array.Empty<byte>();

            if (value.Length == 0 || (value.Length % 2) != 0)
            {
                return false;
            }

            var buffer = new byte[value.Length / 2];

            for (int i = 0; i < buffer.Length; i++)
            {
                if (!TryParseNibble(value[i * 2], out int high) ||
                    !TryParseNibble(value[(i * 2) + 1], out int low))
                {
                    return false;
                }

                buffer[i] = (byte)((high << 4) | low);
            }

            digest = buffer;
            return true;
        }

        private static bool TryParseNibble(char c, out int value)
        {
            if (c >= '0' && c <= '9')
            {
                value = c - '0';
                return true;
            }

            if (c >= 'a' && c <= 'f')
            {
                value = (c - 'a') + 10;
                return true;
            }

            if (c >= 'A' && c <= 'F')
            {
                value = (c - 'A') + 10;
                return true;
            }

            value = 0;
            return false;
        }
    }
}
