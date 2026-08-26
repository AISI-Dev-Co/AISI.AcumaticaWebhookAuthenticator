// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Text;
using AISI.AcumaticaWebhookAuthenticator.Configuration;

namespace AISI.AcumaticaWebhookAuthenticator.Authentication
{
    /// <summary>The sender puts the shared secret itself in a header. Prefer HMAC when the sender can sign.</summary>
    public sealed class SharedSecretAuthenticator : IWebhookAuthenticator
    {
        private readonly IWebhookSecretProvider _secretProvider;
        private readonly string _secretHeader;
        private readonly CredentialVerifier.TryDecode _decode;

        /// <summary>Creates an authenticator.</summary>
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
