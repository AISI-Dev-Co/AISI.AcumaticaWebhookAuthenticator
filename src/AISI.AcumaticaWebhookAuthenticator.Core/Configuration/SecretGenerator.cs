// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Security.Cryptography;
using AISI.AcumaticaWebhookAuthenticator.Signing;

namespace AISI.AcumaticaWebhookAuthenticator.Configuration
{
    /// <summary>Creates random secrets in the text form a <see cref="SecretEncoding"/> expects.</summary>
    public static class SecretGenerator
    {
        /// <summary>Default key size in bytes.</summary>
        public const int DefaultByteLength = 32;

        /// <summary>Smallest key size accepted, in bytes.</summary>
        public const int MinByteLength = 16;

        /// <summary>
        /// Generates a secret from a cryptographic random source. <see cref="SecretEncoding.Utf8"/>
        /// secrets are hex text, which every sender dashboard and header accepts.
        /// </summary>
        /// <param name="encoding">The encoding the secret will be stored under.</param>
        /// <param name="byteLength">Random bytes to draw. At least <see cref="MinByteLength"/>.</param>
        /// <returns>The secret's text form; <see cref="WebhookSecret.Parse"/> accepts it under <paramref name="encoding"/>.</returns>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="byteLength"/> is below <see cref="MinByteLength"/>, or <paramref name="encoding"/> is undefined.
        /// </exception>
        public static string Generate(SecretEncoding encoding, int byteLength = DefaultByteLength)
        {
            if (byteLength < MinByteLength)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(byteLength),
                    byteLength,
                    FormattableString.Invariant($"A secret needs at least {MinByteLength} random bytes."));
            }

            var key = new byte[byteLength];
            using (var random = RandomNumberGenerator.Create())
            {
                random.GetBytes(key);
            }

            switch (encoding)
            {
                case SecretEncoding.Utf8:
                case SecretEncoding.Hex:
                    return SignatureCodec.Encode(key, SignatureEncoding.Hex);

                case SecretEncoding.Base64:
                    return Convert.ToBase64String(key);

                case SecretEncoding.StandardWebhooks:
                    return WebhookSecret.StandardWebhooksPrefix + Convert.ToBase64String(key);

                default:
                    throw new ArgumentOutOfRangeException(nameof(encoding), encoding, "Unknown secret encoding.");
            }
        }
    }
}
