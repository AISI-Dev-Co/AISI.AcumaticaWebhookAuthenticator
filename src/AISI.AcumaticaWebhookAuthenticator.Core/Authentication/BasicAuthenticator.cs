// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using AISI.AcumaticaWebhookAuthenticator.Configuration;

namespace AISI.AcumaticaWebhookAuthenticator.Authentication
{
    /// <summary>The <c>BASIC</c> scheme, RFC 7617 Basic auth against the whole <c>user-id:password</c> secret, which is replayable so prefer HMAC.</summary>
    public sealed class BasicAuthenticator : IWebhookAuthenticator, IChallengeSource
    {
        #region Construction and state
        private const string SchemePrefix = "Basic ";

        private static readonly CredentialVerifier.TryDecode Decode = TryDecodeCredential;

        private readonly IWebhookSecretProvider _secretProvider;

        public BasicAuthenticator(IWebhookSecretProvider secretProvider, string realm = "webhook")
        {
            if (string.IsNullOrWhiteSpace(realm))
            {
                throw new ArgumentException("A realm is required.", nameof(realm));
            }

            if (CredentialVerifier.ContainsHeaderInjection(realm))
            {
                throw new ArgumentException(
                    "The realm cannot contain quotes, backslashes or control characters.",
                    nameof(realm));
            }

            _secretProvider = secretProvider ?? throw new ArgumentNullException(nameof(secretProvider));
            Challenge = "Basic realm=\"" + realm + "\", charset=\"UTF-8\"";
        }
        #endregion

        #region Properties
        public string Code => "BASIC";

        public string Challenge { get; }
        #endregion

        #region Authentication
        public AuthResult Authenticate(WebhookAuthContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return CredentialVerifier.Authenticate(context, _secretProvider, "Authorization", Decode);
        }
        #endregion

        #region Credential decoding
        private static bool TryDecodeCredential(string headerValue, out byte[] credential)
        {
            credential = Array.Empty<byte>();
            if (!CredentialVerifier.TryStripScheme(headerValue, SchemePrefix, out string token))
            {
                return false;
            }

            try
            {
                credential = Convert.FromBase64String(token);
                return true;
            }
            catch (FormatException)
            {
                return false;
            }
        }
        #endregion
    }
}
