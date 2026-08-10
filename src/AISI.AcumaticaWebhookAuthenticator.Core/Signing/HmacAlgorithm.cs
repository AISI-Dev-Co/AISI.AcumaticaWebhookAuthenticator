// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Security.Cryptography;

namespace AISI.AcumaticaWebhookAuthenticator.Signing
{
    /// <summary>
    /// Hash algorithm underlying an HMAC signature scheme.
    /// </summary>
    public enum HmacAlgorithm
    {
        /// <summary>HMAC-SHA256. The correct default; used by GitHub, Shopify, Stripe and most others.</summary>
        Sha256 = 0,

        /// <summary>
        /// HMAC-SHA1. Supported only because a number of long-lived senders still emit it.
        /// Do not choose it for a new integration.
        /// </summary>
        Sha1 = 1,

        /// <summary>HMAC-SHA512.</summary>
        Sha512 = 2,
    }

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
