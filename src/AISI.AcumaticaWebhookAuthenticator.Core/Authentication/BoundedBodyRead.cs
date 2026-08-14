// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;

namespace AISI.AcumaticaWebhookAuthenticator.Authentication
{
    /// <summary>
    /// The outcome of reading a request body through <see cref="BoundedBodyReader"/>.
    /// </summary>
    public readonly struct BoundedBodyRead
    {
        private readonly byte[]? _body;

        private BoundedBodyRead(bool withinLimit, byte[]? body)
        {
            WithinLimit = withinLimit;
            _body = body;
        }

        /// <summary>
        /// Whether the whole body fit inside the limit. When <see langword="false"/> the request
        /// must be rejected; <see cref="Body"/> is empty and the bytes read so far are discarded,
        /// because a truncated body is not a payload — verifying or deserialising it would process
        /// data the sender never sent as a unit.
        /// </summary>
        public bool WithinLimit { get; }

        /// <summary>The body bytes when <see cref="WithinLimit"/>, otherwise empty. Never null.</summary>
        public byte[] Body => _body ?? Array.Empty<byte>();

        /// <summary>Creates a successful read.</summary>
        /// <param name="body">The complete body.</param>
        /// <returns>The result.</returns>
        public static BoundedBodyRead Complete(byte[] body) => new BoundedBodyRead(true, body);

        /// <summary>Creates an over-limit result.</summary>
        /// <returns>The result.</returns>
        public static BoundedBodyRead OverLimit() => new BoundedBodyRead(false, null);
    }
}
