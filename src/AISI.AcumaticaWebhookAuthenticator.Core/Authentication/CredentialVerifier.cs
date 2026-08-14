// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System.Collections.Generic;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using AISI.AcumaticaWebhookAuthenticator.Diagnostics;

namespace AISI.AcumaticaWebhookAuthenticator.Authentication
{
    /// <summary>
    /// The one copy of the credential-comparison pipeline the <c>SECRET</c> and <c>BASIC</c>
    /// schemes share: header lookup, fail-closed secret check, the deliberately
    /// non-short-circuited accumulation over every header value, and the
    /// malformed-versus-mismatched failure triage. The schemes differ only in how a header value
    /// becomes credential bytes, which is what <see cref="TryDecode"/> supplies.
    /// </summary>
    internal static class CredentialVerifier
    {
        /// <summary>Turns one header value into credential bytes, or reports it malformed.</summary>
        internal delegate bool TryDecode(string headerValue, out byte[] credential);

        internal static AuthResult Authenticate(
            WebhookAuthContext context,
            IWebhookSecretProvider secretProvider,
            string credentialHeader,
            TryDecode tryDecode)
        {
            if (!context.TryGetHeaderValues(credentialHeader, out IReadOnlyList<string> headerValues))
            {
                return AuthResult.Fail(AuthFailureCode.CredentialMissing);
            }

            WebhookSecret? secret = secretProvider.GetSecret();
            if (secret is null)
            {
                // A missing secret denies the request. It never degrades to unauthenticated
                // handling, which would turn a blank secret field into an open endpoint.
                return AuthResult.Fail(AuthFailureCode.SecretUnavailable);
            }

            bool matched = false;
            bool anyWellFormed = false;

            // Every value of a repeated header is evaluated, and evaluation does not stop at the
            // first match — the same no-short-circuit discipline WebhookSecret applies across
            // keys, applied across candidates.
            foreach (string headerValue in headerValues)
            {
                if (!tryDecode(headerValue, out byte[] credential))
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

        /// <summary>
        /// Strips a configured prefix from a header value: pass-through when no prefix is
        /// configured, ordinal match required when one is. Shared by every scheme that supports a
        /// sender prefix, so the semantics cannot drift between them.
        /// </summary>
        internal static bool TryStripPrefix(string candidate, string? prefix, out string value)
        {
            if (string.IsNullOrEmpty(prefix))
            {
                value = candidate;
                return true;
            }

            if (!candidate.StartsWith(prefix!, System.StringComparison.Ordinal))
            {
                value = string.Empty;
                return false;
            }

            value = candidate.Substring(prefix!.Length);
            return true;
        }
    }
}
