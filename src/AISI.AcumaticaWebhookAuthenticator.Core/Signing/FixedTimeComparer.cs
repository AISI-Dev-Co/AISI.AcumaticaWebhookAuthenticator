// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System.Runtime.CompilerServices;

namespace AISI.AcumaticaWebhookAuthenticator.Signing
{
    /// <summary>Constant-time equality for secret material. Length is not treated as secret.</summary>
    public static class FixedTimeComparer
    {
        /// <summary>
        /// Compares two byte sequences in time that does not depend on the position of the first
        /// difference.
        /// </summary>
        /// <param name="left">First sequence. May be <see langword="null"/>.</param>
        /// <param name="right">Second sequence. May be <see langword="null"/>.</param>
        /// <returns>
        /// <see langword="true"/> when both are non-null, the same length and byte-for-byte equal.
        /// </returns>
        [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
        public static bool AreEqual(byte[]? left, byte[]? right)
        {
            if (left is null || right is null)
            {
                return false;
            }

            if (left.Length != right.Length)
            {
                return false;
            }

            int accumulator = 0;

            for (int i = 0; i < left.Length; i++)
            {
                // XOR, not subtraction: the difference of two bytes is a signed quantity whose sign
                // bit sets high bits in the accumulator, which happens to work but obscures the
                // invariant. XOR yields zero if and only if the bytes are equal.
                accumulator |= left[i] ^ right[i];
            }

            return accumulator == 0;
        }
    }
}
