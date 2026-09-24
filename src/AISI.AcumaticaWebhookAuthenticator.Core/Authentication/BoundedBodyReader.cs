// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace AISI.AcumaticaWebhookAuthenticator.Authentication
{
    /// <summary>Reads a request body into a byte array, enforcing the size cap while reading.</summary>
    public static class BoundedBodyReader
    {
        /// <summary>The platform's own inbound body cap: 1 MB.</summary>
        public const int DefaultMaxLength = 1024 * 1024;

        internal const int MaxInitialCapacity = 64 * 1024;

        private const int ChunkSize = 16 * 1024;

        /// <summary>Reads <paramref name="source"/> to its end, or to the cap.</summary>
        /// <param name="source">The body stream. Read forward-only; never assumed seekable.</param>
        /// <param name="maxLength">The cap in bytes.</param>
        /// <param name="declaredLength">The declared <c>Content-Length</c>, if any. A hint, not a gate.</param>
        /// <param name="cancellation">The cancellation token.</param>
        /// <exception cref="ArgumentNullException"><paramref name="source"/> is null.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="maxLength"/> is negative.</exception>
        public static async Task<BoundedBodyRead> ReadAsync(
            Stream source,
            int maxLength = DefaultMaxLength,
            long? declaredLength = null,
            CancellationToken cancellation = default)
        {
            using (MemoryStream? buffer = Start(source, maxLength, declaredLength))
            {
                if (buffer is null)
                {
                    return BoundedBodyRead.OverLimit();
                }

                byte[] chunk = new byte[ChunkSize];
                int read;

                while ((read = await source.ReadAsync(chunk, 0, chunk.Length, cancellation).ConfigureAwait(false)) > 0)
                {
                    if (buffer.Length + read > maxLength)
                    {
                        return BoundedBodyRead.OverLimit();
                    }

                    buffer.Write(chunk, 0, read);
                }

                return BoundedBodyRead.Complete(buffer.ToArray());
            }
        }

        private static MemoryStream? Start(Stream source, int maxLength, long? declaredLength)
        {
            if (source is null)
            {
                throw new ArgumentNullException(nameof(source));
            }

            if (maxLength < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(maxLength), maxLength, "The cap cannot be negative.");
            }

            if (declaredLength.HasValue && declaredLength.Value > maxLength)
            {
                return null;
            }

            // Content-Length is sender-controlled, so it sizes the buffer only up to a small bound.
            int capacity = declaredLength.HasValue && declaredLength.Value > 0
                ? (int)Math.Min(declaredLength.Value, MaxInitialCapacity)
                : Math.Min(ChunkSize, maxLength);

            return new MemoryStream(capacity);
        }
    }
}
