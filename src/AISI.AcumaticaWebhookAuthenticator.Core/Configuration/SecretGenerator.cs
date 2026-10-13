// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Security.Cryptography;
using AISI.AcumaticaWebhookAuthenticator.Signing;

namespace AISI.AcumaticaWebhookAuthenticator.Configuration
{
    /// <summary>Creates random secrets in the text form a <see cref="SecretEncoding"/> expects.</summary>
    public static class SecretGenerator
    {
        public const int DefaultByteLength = 32;

        public const int MinByteLength = 16;

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
                // UTF-8 secrets are generated as hex text, which every sender dashboard and header accepts.
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
