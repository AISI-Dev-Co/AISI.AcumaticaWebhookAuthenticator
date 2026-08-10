// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Security.Cryptography;

namespace AISI.AcumaticaWebhookAuthenticator.Signing
{
    /// <summary>
    /// Computes HMAC digests for a <see cref="HmacAlgorithm"/>.
    /// </summary>
    public static class HmacComputer
    {
        /// <summary>
        /// Computes the HMAC of <paramref name="message"/> under <paramref name="key"/>.
        /// </summary>
        /// <param name="algorithm">Hash algorithm to use.</param>
        /// <param name="key">Secret key bytes.</param>
        /// <param name="message">Message bytes to sign.</param>
        /// <returns>The raw digest bytes.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="key"/> or <paramref name="message"/> is null.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="algorithm"/> is not a known value.</exception>
        public static byte[] Compute(HmacAlgorithm algorithm, byte[] key, byte[] message)
        {
            if (key is null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (message is null)
            {
                throw new ArgumentNullException(nameof(message));
            }

            using (HMAC hmac = Create(algorithm, key))
            {
                return hmac.ComputeHash(message);
            }
        }

        private static HMAC Create(HmacAlgorithm algorithm, byte[] key)
        {
            switch (algorithm)
            {
                case HmacAlgorithm.Sha256:
                    return new HMACSHA256(key);
                case HmacAlgorithm.Sha1:
                    return new HMACSHA1(key);
                case HmacAlgorithm.Sha512:
                    return new HMACSHA512(key);
                default:
                    throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Unknown HMAC algorithm.");
            }
        }
    }
}
