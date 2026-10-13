// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;

namespace AISI.AcumaticaWebhookAuthenticator.Authentication
{
    /// <summary>The outcome of reading a request body through <see cref="BoundedBodyReader"/>, where a read not <see cref="WithinLimit"/> must be rejected.</summary>
    public readonly struct BoundedBodyRead
    {
        private readonly byte[]? _body;

        private BoundedBodyRead(bool withinLimit, byte[]? body)
        {
            WithinLimit = withinLimit;
            _body = body;
        }

        public bool WithinLimit { get; }

        public byte[] Body => _body ?? Array.Empty<byte>();

        public static BoundedBodyRead Complete(byte[] body) =>
            new BoundedBodyRead(true, body ?? throw new ArgumentNullException(nameof(body)));

        public static BoundedBodyRead OverLimit() => new BoundedBodyRead(false, null);
    }
}
