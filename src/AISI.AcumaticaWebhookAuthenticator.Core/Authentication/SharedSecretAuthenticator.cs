// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Text;
using AISI.AcumaticaWebhookAuthenticator.Configuration;

namespace AISI.AcumaticaWebhookAuthenticator.Authentication
{
    /// <summary>
    /// The <c>SECRET</c> scheme: the sender puts the shared secret itself in a header.
    /// </summary>
    /// <remarks>
    /// The weakest scheme that still authenticates anything: the credential is not bound to the
    /// request, so anyone who observes it can replay it against any payload. It exists for senders
    /// that offer nothing better than "we will send header X with value Y"; prefer HMAC whenever
    /// the sender supports it. Immutable and safe to share across threads.
    /// </remarks>
    public sealed class SharedSecretAuthenticator : IWebhookAuthenticator
    {
        private readonly IWebhookSecretProvider _secretProvider;
        private readonly string _secretHeader;
        private readonly CredentialVerifier.TryDecode _decode;

        /// <summary>Creates an authenticator.</summary>
        /// <param name="secretProvider">Where the expected secret comes from.</param>
        /// <param name="secretHeader">Header carrying the secret, e.g. <c>X-Api-Key</c>.</param>
        /// <param name="prefix">Prefix the sender puts in front of the secret, or null.</param>
        /// <exception cref="ArgumentNullException"><paramref name="secretProvider"/> is null.</exception>
        /// <exception cref="ArgumentException"><paramref name="secretHeader"/> is null or blank.</exception>
        public SharedSecretAuthenticator(
            IWebhookSecretProvider secretProvider,
            string secretHeader,
            string? prefix = null)
        {
            if (string.IsNullOrWhiteSpace(secretHeader))
            {
                throw new ArgumentException("A secret header name is required.", nameof(secretHeader));
            }

            _secretProvider = secretProvider ?? throw new ArgumentNullException(nameof(secretProvider));
            _secretHeader = secretHeader;
            _decode = (string headerValue, out byte[] credential) =>
            {
                if (!CredentialVerifier.TryStripPrefix(headerValue, prefix, out string value))
                {
                    credential = Array.Empty<byte>();
                    return false;
                }

                credential = Encoding.UTF8.GetBytes(value);
                return true;
            };
        }

        /// <inheritdoc/>
        public string Code => "SECRET";

        /// <inheritdoc/>
        public AuthResult Authenticate(WebhookAuthContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return CredentialVerifier.Authenticate(context, _secretProvider, _secretHeader, _decode);
        }
    }
}
