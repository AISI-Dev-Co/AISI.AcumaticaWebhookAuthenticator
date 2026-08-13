// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System.Runtime.CompilerServices;

namespace AISI.AcumaticaWebhookAuthenticator.Signing
{
    /// <summary>
    /// Constant-time equality for secret material.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This exists because <c>System.Security.Cryptography.CryptographicOperations.FixedTimeEquals</c>
    /// is not available on the .NET Framework 4.8 runtime that Acumatica 2025 R2 runs on — it was
    /// introduced in .NET Standard 2.1, and net48 implements .NET Standard 2.0 only.
    /// </para>
    /// <para>
    /// Every comparison of a computed signature against a caller-supplied one must go through this
    /// type. Using <c>==</c> on strings or <c>SequenceEqual</c> on byte arrays leaks the position of
    /// the first differing byte through timing, which is enough to forge a signature one byte at a
    /// time.
    /// </para>
    /// <para>
    /// Following the same contract as the BCL implementation, the <em>lengths</em> of the two inputs
    /// are not treated as secret and a length mismatch returns early. For signature verification this
    /// is not a weakness: the length is fixed by the hash algorithm and is public.
    /// </para>
    /// </remarks>
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
