// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using AISI.AcumaticaWebhookAuthenticator.Configuration;

namespace AISI.AcumaticaWebhookAuthenticator.Authentication
{
    /// <summary>RFC 7617 HTTP Basic. Store the whole <c>user-id:password</c> string as the secret.</summary>
    public sealed class BasicAuthenticator : IWebhookAuthenticator, IChallengeSource
    {
        #region Construction and state
        private const string SchemePrefix = "Basic ";

        private static readonly CredentialVerifier.TryDecode Decode = TryDecodeCredential;

        private readonly IWebhookSecretProvider _secretProvider;

        /// <summary>Creates an authenticator. Realm is for the 401 challenge only.</summary>
        public BasicAuthenticator(IWebhookSecretProvider secretProvider, string realm = "webhook")
        {
            if (string.IsNullOrWhiteSpace(realm))
            {
                throw new ArgumentException("A realm is required.", nameof(realm));
            }

            foreach (char c in realm)
            {
                if (c == '"' || c == '\\' || char.IsControl(c))
                {
                    throw new ArgumentException(
                        "The realm cannot contain quotes, backslashes or control characters.",
                        nameof(realm));
                }
            }

            _secretProvider = secretProvider ?? throw new ArgumentNullException(nameof(secretProvider));
            Challenge = "Basic realm=\"" + realm + "\", charset=\"UTF-8\"";
        }
        #endregion

        #region Authentication
        /// <inheritdoc/>
        public string Code => "BASIC";

        /// <summary>The <c>WWW-Authenticate</c> value to send with a 401.</summary>
        public string Challenge { get; }

        /// <inheritdoc/>
        public AuthResult Authenticate(WebhookAuthContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return CredentialVerifier.Authenticate(context, _secretProvider, "Authorization", Decode);
        }
        #endregion

        #region Internals
        private static bool TryDecodeCredential(string headerValue, out byte[] credential)
        {
            credential = Array.Empty<byte>();

            // RFC 7235: the scheme token is case-insensitive; extra spaces before the token are
            // tolerated, as servers conventionally do.
            if (headerValue.Length <= SchemePrefix.Length ||
                !headerValue.StartsWith(SchemePrefix, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            string token = headerValue.Substring(SchemePrefix.Length).Trim(' ');
            if (token.Length == 0)
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
                // Attacker-suppliable input; must never escape as a 500.
                return false;
            }
        }
        #endregion
    }
}
