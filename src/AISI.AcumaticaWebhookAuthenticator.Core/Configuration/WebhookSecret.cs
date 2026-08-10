// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Text;
using AISI.AcumaticaWebhookAuthenticator.Signing;

namespace AISI.AcumaticaWebhookAuthenticator.Configuration
{
    /// <summary>
    /// A signing secret, optionally with a second secret valid during a rotation overlap.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Rotation is not an edge case. A sender rotating its signing secret emits requests signed with
    /// either the old or the new one for the length of the overlap window, and a verifier that knows
    /// only one of them drops roughly half the traffic for the duration. Verification tries the
    /// current secret first, then the rotating secret if one is present and unexpired.
    /// </para>
    /// <para>
    /// Which of the two matched is not reported. It is not needed operationally and reporting it
    /// would turn verification into an oracle for which secret is live.
    /// </para>
    /// </remarks>
    public sealed class WebhookSecret
    {
        private readonly byte[] _current;
        private readonly byte[]? _rotating;
        private readonly DateTimeOffset? _rotatingExpiresOn;

        private WebhookSecret(byte[] current, byte[]? rotating, DateTimeOffset? rotatingExpiresOn)
        {
            _current = current;
            _rotating = rotating;
            _rotatingExpiresOn = rotatingExpiresOn;
        }

        /// <summary>
        /// Creates a secret from raw key bytes.
        /// </summary>
        /// <param name="current">The active secret.</param>
        /// <returns>The secret.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="current"/> is null.</exception>
        public static WebhookSecret FromBytes(byte[] current)
        {
            if (current is null)
            {
                throw new ArgumentNullException(nameof(current));
            }

            return new WebhookSecret(current, null, null);
        }

        /// <summary>
        /// Creates a secret from its UTF-8 text form. This is what most senders mean by a
        /// "signing secret" or "webhook secret" pasted from a dashboard.
        /// </summary>
        /// <param name="current">The active secret.</param>
        /// <returns>The secret.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="current"/> is null.</exception>
        public static WebhookSecret FromUtf8(string current)
        {
            if (current is null)
            {
                throw new ArgumentNullException(nameof(current));
            }

            return FromBytes(Encoding.UTF8.GetBytes(current));
        }

        /// <summary>
        /// Creates a secret from a hex-encoded key.
        /// </summary>
        /// <param name="current">Hex-encoded secret.</param>
        /// <returns>The secret.</returns>
        /// <exception cref="FormatException">The value is not valid hex.</exception>
        public static WebhookSecret FromHex(string current)
        {
            if (!SignatureCodec.TryDecode(current, SignatureEncoding.Hex, out byte[] bytes))
            {
                throw new FormatException("The secret is not valid hexadecimal.");
            }

            return FromBytes(bytes);
        }

        /// <summary>
        /// Creates a secret from a base64-encoded key.
        /// </summary>
        /// <param name="current">Base64-encoded secret.</param>
        /// <returns>The secret.</returns>
        /// <exception cref="FormatException">The value is not valid base64.</exception>
        public static WebhookSecret FromBase64(string current)
        {
            if (!SignatureCodec.TryDecode(current, SignatureEncoding.Base64, out byte[] bytes))
            {
                throw new FormatException("The secret is not valid base64.");
            }

            return FromBytes(bytes);
        }

        /// <summary>
        /// Returns a copy of this secret with a rotating counterpart valid until an expiry.
        /// </summary>
        /// <param name="rotating">The other secret accepted during the overlap.</param>
        /// <param name="expiresOn">
        /// When the overlap ends. After this instant the rotating secret is no longer accepted, so a
        /// forgotten rotation closes itself rather than leaving a retired secret live indefinitely.
        /// </param>
        /// <returns>A new secret carrying the overlap.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="rotating"/> is null.</exception>
        public WebhookSecret WithRotating(byte[] rotating, DateTimeOffset expiresOn)
        {
            if (rotating is null)
            {
                throw new ArgumentNullException(nameof(rotating));
            }

            return new WebhookSecret(_current, rotating, expiresOn);
        }

        /// <summary>
        /// Returns a copy of this secret with a rotating counterpart supplied as UTF-8 text.
        /// </summary>
        /// <param name="rotating">The other secret accepted during the overlap.</param>
        /// <param name="expiresOn">When the overlap ends.</param>
        /// <returns>A new secret carrying the overlap.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="rotating"/> is null.</exception>
        public WebhookSecret WithRotatingUtf8(string rotating, DateTimeOffset expiresOn)
        {
            if (rotating is null)
            {
                throw new ArgumentNullException(nameof(rotating));
            }

            return WithRotating(Encoding.UTF8.GetBytes(rotating), expiresOn);
        }

        /// <summary>
        /// The secrets to verify against, in priority order, at a given instant.
        /// </summary>
        /// <param name="asOf">The instant to evaluate the rotation window against.</param>
        /// <returns>The current secret, then the rotating secret when it is present and unexpired.</returns>
        public IReadOnlyList<byte[]> CandidatesAsOf(DateTimeOffset asOf)
        {
            if (_rotating is null || _rotatingExpiresOn is null || asOf > _rotatingExpiresOn.Value)
            {
                return new[] { _current };
            }

            return new[] { _current, _rotating };
        }
    }

    /// <summary>
    /// Supplies the signing secret for an endpoint.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The interface exists so that secret storage is a deployment decision rather than a library
    /// one. The intended production implementation reads a <c>[PXRSACryptString]</c> field from the
    /// ERP database, which is Acumatica's own pattern for third-party integration credentials: it is
    /// encrypted at rest, it is editable by an administrator without a redeployment, it survives the
    /// platform's move off .NET Framework because it is an ORM concern rather than a configuration
    /// file one, and it is the only option that works on SaaS, where there is no file system and no
    /// environment to read.
    /// </para>
    /// <para>
    /// Implementations are called once per request and should cache accordingly.
    /// </para>
    /// </remarks>
    public interface IWebhookSecretProvider
    {
        /// <summary>
        /// Returns the secret to verify against, or <see langword="null"/> when none is configured.
        /// A null return denies the request; it never falls back to unauthenticated handling.
        /// </summary>
        /// <returns>The secret, or <see langword="null"/>.</returns>
        WebhookSecret? GetSecret();
    }

    /// <summary>
    /// An <see cref="IWebhookSecretProvider"/> over a secret already in memory.
    /// </summary>
    /// <remarks>
    /// Intended for tests and for the signature tester. Using it in production means a secret
    /// compiled into an assembly, which cannot be rotated without a redeployment and will be
    /// recoverable by anyone who can read the DLL.
    /// </remarks>
    public sealed class StaticSecretProvider : IWebhookSecretProvider
    {
        private readonly WebhookSecret _secret;

        /// <summary>Creates a provider over a fixed secret.</summary>
        /// <param name="secret">The secret to return.</param>
        /// <exception cref="ArgumentNullException"><paramref name="secret"/> is null.</exception>
        public StaticSecretProvider(WebhookSecret secret)
        {
            _secret = secret ?? throw new ArgumentNullException(nameof(secret));
        }

        /// <inheritdoc/>
        public WebhookSecret? GetSecret() => _secret;
    }
}
