// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Globalization;
using System.Text;

namespace AISI.AcumaticaWebhookAuthenticator.Signing
{
    /// <summary>Hex / base64 encoding for signature digests.</summary>
    public static class SignatureCodec
    {
        #region Encoding and decoding
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

        /// <summary>Decodes a signature from its wire encoding, returning false rather than throwing on absent or hostile input.</summary>
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
                    return TryDecodeBase64(value!, out digest);

                default:
                    return false;
            }
        }
        #endregion

        #region Internals
        private static bool TryDecodeBase64(string value, out byte[] digest)
        {
            digest = Array.Empty<byte>();

            try
            {
                digest = Convert.FromBase64String(value);
                return true;
            }
            catch (FormatException)
            {
                return false;
            }
        }

        private static bool TryDecodeHex(string value, out byte[] digest)
        {
            digest = Array.Empty<byte>();

            if ((value.Length % 2) != 0)
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
        #endregion
    }
}
