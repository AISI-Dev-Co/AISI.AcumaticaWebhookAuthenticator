// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Text;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using AISI.AcumaticaWebhookAuthenticator.Diagnostics;

namespace AISI.AcumaticaWebhookAuthenticator.Authentication
{
    /// <summary>
    /// The <c>BASIC</c> scheme: RFC 7617 HTTP Basic authentication over the <c>Authorization</c>
    /// header.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The secret is the <em>whole</em> <c>user-id:password</c> credential, stored as one value —
    /// build it with <c>WebhookSecret.FromUtf8("svc-sender:hunter2")</c>. The decoded credential is
    /// compared against it in one fixed-time operation. Not splitting at the colon is deliberate:
    /// there is no username lookup step to time-attack, no user-enumeration distinction between
    /// "unknown user" and "wrong password", and rotation (a new username, a new password, or both)
    /// is just <see cref="WebhookSecret.WithRotatingUtf8"/> like every other scheme.
    /// </para>
    /// <para>
    /// Like the <c>SECRET</c> scheme, the credential is not bound to the request and is replayable
    /// by anyone who observes it. It exists for senders that offer Basic authentication and nothing
    /// better.
    /// </para>
    /// <para>
    /// On a 401 the adapter should send <see cref="Challenge"/> as <c>WWW-Authenticate</c>; RFC
    /// 7235 requires the challenge, and some senders will not retry without it.
    /// </para>
    /// <para>
    /// Instances are immutable and safe to share across threads.
    /// </para>
    /// </remarks>
    public sealed class BasicAuthenticator : IWebhookAuthenticator
    {
        private const string SchemePrefix = "Basic ";

        private readonly IWebhookSecretProvider _secretProvider;

        /// <summary>
        /// Creates an authenticator.
        /// </summary>
        /// <param name="secretProvider">
        /// Where the expected credential comes from. The secret is the full
        /// <c>user-id:password</c> string, UTF-8 encoded.
        /// </param>
        /// <param name="realm">
        /// Realm to present in <see cref="Challenge"/>. Defaults to <c>webhook</c>.
        /// </param>
        /// <exception cref="ArgumentNullException"><paramref name="secretProvider"/> is null.</exception>
        /// <exception cref="ArgumentException">
        /// <paramref name="realm"/> is null, blank, or contains a character that cannot appear in a
        /// quoted-string header value. A realm containing a double quote or a control character
        /// would corrupt the <c>WWW-Authenticate</c> header — or worse, split it — so it is
        /// rejected at construction rather than emitted.
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

        /// <inheritdoc/>
        public string Code => "BASIC";

        /// <summary>
        /// The <c>WWW-Authenticate</c> value to send with a 401. Sending it is the adapter's job;
        /// the core has no response object to set it on.
        /// </summary>
        public string Challenge { get; }

        /// <inheritdoc/>
        public AuthResult Authenticate(WebhookAuthContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (!context.TryGetHeaderValues("Authorization", out IReadOnlyList<string> headerValues))
            {
                return AuthResult.Fail(AuthFailureCode.CredentialMissing);
            }

            WebhookSecret? secret = _secretProvider.GetSecret();
            if (secret is null)
            {
                return AuthResult.Fail(AuthFailureCode.SecretUnavailable);
            }

            bool matched = false;
            bool anyWellFormed = false;

            foreach (string headerValue in headerValues)
            {
                if (!TryDecodeCredential(headerValue, out byte[] credential))
                {
                    continue;
                }

                anyWellFormed = true;
                matched |= secret.MatchesValue(credential, context.ReceivedOn);
            }

            if (matched)
            {
                return AuthResult.Success();
            }

            return AuthResult.Fail(
                anyWellFormed ? AuthFailureCode.CredentialMismatch : AuthFailureCode.CredentialMalformed);
        }

        private static bool TryDecodeCredential(string headerValue, out byte[] credential)
        {
            credential = Array.Empty<byte>();

            // RFC 7235: the scheme token is case-insensitive. The separator must be present; more
            // than one space between scheme and token is tolerated, as servers conventionally do.
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
                // Malformed base64 is an attacker-suppliable input, not an exceptional condition;
                // it must never escape as a 500.
                return false;
            }
        }
    }
}
