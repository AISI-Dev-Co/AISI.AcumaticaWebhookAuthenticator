// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using AISI.AcumaticaWebhookAuthenticator.Configuration;

namespace AISI.AcumaticaWebhookAuthenticator.Authentication
{
    /// <summary>
    /// The <c>BASIC</c> scheme: RFC 7617 HTTP Basic authentication over the <c>Authorization</c>
    /// header.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The secret is the <em>whole</em> <c>user-id:password</c> credential as one value —
    /// <c>WebhookSecret.FromUtf8("svc-sender:hunter2")</c> — compared in one fixed-time operation.
    /// Not splitting at the colon is deliberate: no username lookup to time-attack, no
    /// user-enumeration distinction, and rotation works like every other scheme.
    /// </para>
    /// <para>
    /// Replayable by anyone who observes it, like <c>SECRET</c>; for senders that offer Basic and
    /// nothing better. On a 401 the host should send <see cref="Challenge"/> (published through
    /// <see cref="IChallengeSource"/>) — RFC 7235 requires it, and some senders will not retry
    /// without it. Immutable and safe to share across threads.
    /// </para>
    /// </remarks>
    public sealed class BasicAuthenticator : IWebhookAuthenticator, IChallengeSource
    {
        #region Construction and state
        private const string SchemePrefix = "Basic ";

        private static readonly CredentialVerifier.TryDecode Decode = TryDecodeCredential;

        private readonly IWebhookSecretProvider _secretProvider;

        /// <summary>Creates an authenticator.</summary>
        /// <param name="secretProvider">Where the expected <c>user-id:password</c> credential comes from.</param>
        /// <param name="realm">Realm for <see cref="Challenge"/>. Defaults to <c>webhook</c>.</param>
        /// <exception cref="ArgumentNullException"><paramref name="secretProvider"/> is null.</exception>
        /// <exception cref="ArgumentException">
        /// <paramref name="realm"/> is blank or contains a quote, backslash or control character —
        /// which would corrupt or split the <c>WWW-Authenticate</c> header.
        /// </exception>
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
