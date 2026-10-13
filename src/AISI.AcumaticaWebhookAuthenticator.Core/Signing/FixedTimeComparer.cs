// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System.Runtime.CompilerServices;

namespace AISI.AcumaticaWebhookAuthenticator.Signing
{
    /// <summary>Constant-time equality for secret material, where length is not treated as secret.</summary>
    public static class FixedTimeComparer
    {
        /// <summary>Whether both sequences are non-null and byte-for-byte equal, compared in time independent of where they first differ.</summary>
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

            // Every byte is folded into one accumulator, and NoOptimization stops the JIT reintroducing an early exit.
            int accumulator = 0;

            for (int i = 0; i < left.Length; i++)
            {
                accumulator |= left[i] ^ right[i];
            }

            return accumulator == 0;
        }
    }
}
