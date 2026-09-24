// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using AISI.AcumaticaWebhookAuthenticator.Diagnostics;

namespace AISI.AcumaticaWebhookAuthenticator.Authentication
{
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
                // Fail closed: a blank secret field must never become an open endpoint.
                return AuthResult.Fail(AuthFailureCode.SecretUnavailable);
            }

            bool matched = false;
            bool anyWellFormed = false;

            // Not short-circuited: every candidate is compared so timing does not reveal which matched.
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
        /// Strips an exact (ordinal) sender prefix, passing the value through when none is configured.
        /// Used by the SECRET and HMAC schemes.
        /// </summary>
        internal static bool TryStripPrefix(string candidate, string? prefix, out string value)
        {
            if (string.IsNullOrEmpty(prefix))
            {
                value = candidate;
                return true;
            }

            if (!candidate.StartsWith(prefix!, StringComparison.Ordinal))
            {
                value = string.Empty;
                return false;
            }

            value = candidate.Substring(prefix!.Length);
            return true;
        }

        /// <summary>
        /// Strips a case-insensitive RFC 7235 auth-scheme prefix and surrounding spaces; false when
        /// the prefix is absent or nothing follows it. Used by the BASIC and JWT schemes.
        /// </summary>
        internal static bool TryStripScheme(string headerValue, string scheme, out string token)
        {
            if (!headerValue.StartsWith(scheme, StringComparison.OrdinalIgnoreCase))
            {
                token = string.Empty;
                return false;
            }

            token = headerValue.Substring(scheme.Length).Trim(' ');
            return token.Length > 0;
        }

        /// <summary>Whether a value would corrupt or split a quoted <c>WWW-Authenticate</c> header.</summary>
        internal static bool ContainsHeaderInjection(string value)
        {
            foreach (char c in value)
            {
                if (c == '"' || c == '\\' || char.IsControl(c))
                {
                    return true;
                }
            }

            return false;
        }
    }
}
