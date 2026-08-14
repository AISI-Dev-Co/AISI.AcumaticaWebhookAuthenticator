// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Text;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using AISI.AcumaticaWebhookAuthenticator.Diagnostics;

namespace AISI.AcumaticaWebhookAuthenticator.Authentication
{
    /// <summary>
    /// The <c>SECRET</c> scheme: the sender puts the shared secret itself in a header, and the
    /// request authenticates when it equals a live secret.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the weakest scheme that still authenticates anything: the credential is not bound to
    /// the request, so anyone who observes it — a proxy log, a request capture, a misdirected
    /// request — can replay it against any payload indefinitely. It exists because a long tail of
    /// senders (internal systems, low-stakes SaaS products) offer nothing better than "we will send
    /// header X with value Y". Prefer an HMAC scheme whenever the sender supports one.
    /// </para>
    /// <para>
    /// Comparison happens inside <see cref="WebhookSecret.MatchesValue"/>: fixed-time per
    /// candidate, both live secrets always evaluated, so rotation neither leaks which secret is
    /// live nor drops traffic mid-overlap.
    /// </para>
    /// <para>
    /// Instances are immutable and safe to share across threads.
    /// </para>
    /// </remarks>
    public sealed class SharedSecretAuthenticator : IWebhookAuthenticator
    {
        private readonly IWebhookSecretProvider _secretProvider;
        private readonly string _secretHeader;
        private readonly string? _prefix;

        /// <summary>
        /// Creates an authenticator.
        /// </summary>
        /// <param name="secretProvider">Where the expected secret comes from.</param>
        /// <param name="secretHeader">Header carrying the secret, e.g. <c>X-Api-Key</c>.</param>
        /// <param name="prefix">
        /// Prefix the sender puts in front of the secret, e.g. <c>Bearer </c> for senders that
        /// misuse the Authorization header for a static token. Null when there is none.
        /// </param>
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
            _prefix = prefix;
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

            if (!context.TryGetHeaderValues(_secretHeader, out IReadOnlyList<string> headerValues))
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

            // Every value of a repeated header is evaluated, and evaluation does not stop at the
            // first match — the same no-short-circuit discipline WebhookSecret applies across keys,
            // applied across candidates.
            foreach (string headerValue in headerValues)
            {
                if (!TryStripPrefix(headerValue, out string credential))
                {
                    continue;
                }

                anyWellFormed = true;
                matched |= secret.MatchesValue(Encoding.UTF8.GetBytes(credential), context.ReceivedOn);
            }

            if (matched)
            {
                return AuthResult.Success();
            }

            return AuthResult.Fail(
                anyWellFormed ? AuthFailureCode.CredentialMismatch : AuthFailureCode.CredentialMalformed);
        }

        private bool TryStripPrefix(string candidate, out string credential)
        {
            if (string.IsNullOrEmpty(_prefix))
            {
                credential = candidate;
                return true;
            }

            if (!candidate.StartsWith(_prefix!, StringComparison.Ordinal))
            {
                credential = string.Empty;
                return false;
            }

            credential = candidate.Substring(_prefix!.Length);
            return true;
        }
    }
}
