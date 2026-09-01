// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using AISI.AcumaticaWebhookAuthenticator.Diagnostics;
using AISI.AcumaticaWebhookAuthenticator.Signing;

namespace AISI.AcumaticaWebhookAuthenticator.Authentication
{
    /// <summary>
    /// The <c>JWT</c> scheme: compact JWS (HS256 / HS512) carried in a header.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The HMAC covers the JWT's own <c>header.payload</c> bytes (RFC 7515). It does
    /// <em>not</em> MAC the HTTP body. That is the same class of unbound credential as
    /// <c>SECRET</c> and <c>BASIC</c> unless the payload carries the body-hash claim
    /// (<see cref="JwtAuthOptions.BodyHashClaimName"/>, SHA-256 of the raw body, compared
    /// constant-time). The default configuration requires that claim. Prefer a real
    /// body-HMAC scheme (<see cref="HmacAuthenticator"/>) when the sender can sign the
    /// request bytes.
    /// </para>
    /// <para>
    /// Audience defaults to the webhook registration id so a reused secret cannot be
    /// presented to a different webhook. <c>iss</c> is checked only when configured.
    /// Immutable and safe to share across threads.
    /// </para>
    /// </remarks>
    public sealed class JwtAuthenticator : IWebhookAuthenticator, IChallengeSource
    {
        private readonly IWebhookSecretProvider _secretProvider;
        private readonly string _tokenHeader;
        private readonly string? _schemePrefix;
        private readonly HmacAlgorithm _algorithm;
        private readonly string _jwtAlg;
        private readonly string? _issuer;
        private readonly string? _audience;
        private readonly bool _bindAudienceToWebhookId;
        private readonly TimeSpan _clockSkew;
        private readonly bool _requireExpiration;
        private readonly bool _requireBodyHash;
        private readonly int _maxTokenLength;

        /// <summary>Creates an authenticator. Options are snapshotted here and never read again.</summary>
        public JwtAuthenticator(JwtAuthOptions options)
        {
            if (options is null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            string? problem = options.DescribeMisconfiguration();
            if (problem is object)
            {
                throw new ArgumentException(problem, nameof(options));
            }

            _secretProvider = options.SecretProvider;
            _tokenHeader = options.TokenHeader;
            _schemePrefix = options.SchemePrefix;
            _algorithm = options.Algorithm;
            _jwtAlg = options.JwtAlgorithmName!;
            _issuer = string.IsNullOrEmpty(options.Issuer) ? null : options.Issuer;
            _audience = string.IsNullOrEmpty(options.Audience) ? null : options.Audience;
            _bindAudienceToWebhookId = options.BindAudienceToWebhookId;
            _clockSkew = options.ClockSkew;
            _requireExpiration = options.RequireExpiration;
            _requireBodyHash = options.RequireBodyHash;
            _maxTokenLength = options.MaxTokenLength;
            Challenge = BuildChallenge(_tokenHeader, _schemePrefix);
        }

        /// <inheritdoc/>
        public string Code => "JWT";

        /// <summary>
        /// RFC 6750-style <c>WWW-Authenticate</c> value for a 401, matching
        /// <see cref="JwtAuthOptions.SchemePrefix"/> (or the token header when there is no prefix).
        /// </summary>
        public string Challenge { get; }

        /// <inheritdoc/>
        public AuthResult Authenticate(WebhookAuthContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            try
            {
                return AuthenticateCore(context);
            }
            catch (Exception exception) when (
                exception is ArgumentOutOfRangeException ||
                exception is OverflowException ||
                exception is FormatException ||
                exception is DecoderFallbackException ||
                exception is InvalidOperationException)
            {
                // Signed junk, overflowed NumericDate, or a hostile compact token: 401, never 500.
                return AuthResult.Fail(AuthFailureCode.JwtMalformed);
            }
        }

        private AuthResult AuthenticateCore(WebhookAuthContext context)
        {
            if (!context.TryGetHeaderValues(_tokenHeader, out IReadOnlyList<string> headerValues))
            {
                return AuthResult.Fail(AuthFailureCode.CredentialMissing);
            }

            WebhookSecret? secret = _secretProvider.GetSecret();
            if (secret is null)
            {
                return AuthResult.Fail(AuthFailureCode.SecretUnavailable);
            }

            AuthResult? firstFailure = null;
            bool anyWellFormed = false;

            foreach (string headerValue in headerValues)
            {
                if (!TryExtractToken(headerValue, out string compact))
                {
                    continue;
                }

                anyWellFormed = true;
                AuthResult result = AuthenticateToken(compact, secret, context);
                if (result.Succeeded)
                {
                    return result;
                }

                if (firstFailure is null)
                {
                    firstFailure = result;
                }
            }

            if (!anyWellFormed)
            {
                return AuthResult.Fail(AuthFailureCode.CredentialMalformed);
            }

            return firstFailure ?? AuthResult.Fail(AuthFailureCode.JwtMalformed);
        }

        private bool TryExtractToken(string headerValue, out string token)
        {
            token = string.Empty;

            if (string.IsNullOrEmpty(_schemePrefix))
            {
                string trimmed = headerValue.Trim();
                if (trimmed.Length == 0)
                {
                    return false;
                }

                token = trimmed;
                return true;
            }

            if (headerValue.Length <= _schemePrefix!.Length ||
                !headerValue.StartsWith(_schemePrefix, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            token = headerValue.Substring(_schemePrefix.Length).Trim(' ');
            return token.Length > 0;
        }

        private AuthResult AuthenticateToken(string compact, WebhookSecret secret, WebhookAuthContext context)
        {
            if (compact.Length > _maxTokenLength)
            {
                return AuthResult.Fail(AuthFailureCode.JwtMalformed);
            }

            int firstDot = compact.IndexOf('.');
            int secondDot = firstDot < 0 ? -1 : compact.IndexOf('.', firstDot + 1);
            if (firstDot <= 0 || secondDot < 0 || compact.IndexOf('.', secondDot + 1) >= 0)
            {
                return AuthResult.Fail(AuthFailureCode.JwtMalformed);
            }

            string headerSegment = compact.Substring(0, firstDot);
            string payloadSegment = compact.Substring(firstDot + 1, secondDot - firstDot - 1);
            string signatureSegment = compact.Substring(secondDot + 1);

            if (!TryBase64UrlDecode(headerSegment, out byte[] headerBytes))
            {
                return AuthResult.Fail(AuthFailureCode.JwtMalformed);
            }

            string headerJson;
            try
            {
                headerJson = Encoding.UTF8.GetString(headerBytes);
            }
            catch (ArgumentException)
            {
                return AuthResult.Fail(AuthFailureCode.JwtMalformed);
            }

            if (!JwtJsonObject.TryParse(headerJson, out JwtJsonObject header) || header.HasDuplicates)
            {
                return AuthResult.Fail(AuthFailureCode.JwtMalformed);
            }

            if (header.Contains("crit"))
            {
                // RFC 7515 §4.1.11: unsupported crit members (we support none) MUST reject the JWS.
                return AuthResult.Fail(AuthFailureCode.JwtCriticalHeader);
            }

            if (!header.TryGetString("alg", out string alg) ||
                !string.Equals(alg, _jwtAlg, StringComparison.Ordinal))
            {
                return AuthResult.Fail(AuthFailureCode.JwtAlgorithmRejected);
            }

            if (signatureSegment.Length == 0 ||
                !TryBase64UrlDecode(signatureSegment, out byte[] signature))
            {
                return AuthResult.Fail(AuthFailureCode.JwtMalformed);
            }

            byte[] signingInput = Encoding.ASCII.GetBytes(headerSegment + "." + payloadSegment);
            if (!secret.MatchesAny(_algorithm, signingInput, new[] { signature }, context.ReceivedOn))
            {
                return AuthResult.Fail(AuthFailureCode.SignatureMismatch);
            }

            if (!TryBase64UrlDecode(payloadSegment, out byte[] payloadBytes))
            {
                return AuthResult.Fail(AuthFailureCode.JwtMalformed);
            }

            string payloadJson;
            try
            {
                payloadJson = Encoding.UTF8.GetString(payloadBytes);
            }
            catch (ArgumentException)
            {
                return AuthResult.Fail(AuthFailureCode.JwtMalformed);
            }

            if (!JwtJsonObject.TryParse(payloadJson, out JwtJsonObject payload) || payload.HasDuplicates)
            {
                return AuthResult.Fail(AuthFailureCode.JwtMalformed);
            }

            if (_requireExpiration && !payload.Contains("exp"))
            {
                return AuthResult.Fail(AuthFailureCode.JwtExpirationMissing);
            }

            if (payload.Contains("exp"))
            {
                if (!payload.TryGetInt64("exp", out long exp) ||
                    !TryUnixInstant(exp, _clockSkew, addSkew: true, out DateTimeOffset expires))
                {
                    return AuthResult.Fail(AuthFailureCode.JwtMalformed);
                }

                if (context.ReceivedOn > expires)
                {
                    return AuthResult.Fail(AuthFailureCode.JwtExpired);
                }
            }

            if (payload.Contains("nbf"))
            {
                if (!payload.TryGetInt64("nbf", out long nbf) ||
                    !TryUnixInstant(nbf, _clockSkew, addSkew: false, out DateTimeOffset notBefore))
                {
                    return AuthResult.Fail(AuthFailureCode.JwtMalformed);
                }

                if (context.ReceivedOn < notBefore)
                {
                    return AuthResult.Fail(AuthFailureCode.JwtNotYetValid);
                }
            }

            if (_issuer is object)
            {
                if (!payload.TryGetString("iss", out string iss) || iss != _issuer)
                {
                    return AuthResult.Fail(AuthFailureCode.JwtIssuerMismatch);
                }
            }

            string? expectedAudience = ResolveAudience(context);
            if (expectedAudience is object && !AudienceContains(payload, expectedAudience))
            {
                return AuthResult.Fail(AuthFailureCode.JwtAudienceMismatch);
            }

            bool hasBodyHash = payload.Contains(JwtAuthOptions.BodyHashClaimName);
            if (_requireBodyHash && !hasBodyHash)
            {
                return AuthResult.Fail(AuthFailureCode.JwtBodyHashMissing);
            }

            if (hasBodyHash)
            {
                if (!payload.TryGetString(JwtAuthOptions.BodyHashClaimName, out string provided) ||
                    !TryBase64UrlDecode(provided, out byte[] providedHash) ||
                    providedHash.Length != 32)
                {
                    return AuthResult.Fail(AuthFailureCode.JwtMalformed);
                }

                byte[] actual = ComputeBodyHash(context.Body);
                if (!FixedTimeComparer.AreEqual(actual, providedHash))
                {
                    return AuthResult.Fail(AuthFailureCode.JwtBodyHashMismatch);
                }
            }

            return AuthResult.Success();
        }

        private string? ResolveAudience(WebhookAuthContext context)
        {
            if (_audience is object)
            {
                return _audience;
            }

            if (!_bindAudienceToWebhookId)
            {
                return null;
            }

            return context.WebhookId is Guid id ? id.ToString("D") : string.Empty;
        }

        internal static string Compact(HmacAlgorithm algorithm, byte[] key, string payloadJson)
        {
            string alg = algorithm == HmacAlgorithm.Sha512 ? "HS512" : "HS256";
            string headerJson = "{\"alg\":\"" + alg + "\",\"typ\":\"JWT\"}";
            string header = Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
            string payload = Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
            byte[] signature = HmacComputer.Compute(
                algorithm,
                key,
                Encoding.ASCII.GetBytes(header + "." + payload));
            return header + "." + payload + "." + Base64UrlEncode(signature);
        }

        internal static string Base64UrlEncode(byte[] data)
        {
            return Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        internal static byte[] ComputeBodyHash(byte[] body)
        {
            using (SHA256 sha = SHA256.Create())
            {
                return sha.ComputeHash(body ?? Array.Empty<byte>());
            }
        }

        private static string BuildChallenge(string tokenHeader, string? schemePrefix)
        {
            string scheme;
            if (schemePrefix is object && schemePrefix.Length > 0)
            {
                scheme = schemePrefix.Trim();
                int space = scheme.IndexOf(' ');
                if (space > 0)
                {
                    scheme = scheme.Substring(0, space);
                }
            }
            else
            {
                scheme = tokenHeader.Trim();
            }

            if (scheme.Length == 0 || ContainsHeaderInjection(scheme))
            {
                scheme = "Bearer";
            }

            return scheme + " realm=\"webhook\"";
        }

        private static bool ContainsHeaderInjection(string value)
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

        private static bool TryUnixInstant(long seconds, TimeSpan skew, bool addSkew, out DateTimeOffset value)
        {
            value = default;
            DateTimeOffset unix;
            try
            {
                unix = DateTimeOffset.FromUnixTimeSeconds(seconds);
            }
            catch (ArgumentOutOfRangeException)
            {
                return false;
            }

            try
            {
                value = addSkew ? unix.Add(skew) : unix.Subtract(skew);
                return true;
            }
            catch (ArgumentOutOfRangeException)
            {
                return false;
            }
        }

        private static bool TryBase64UrlDecode(string value, out byte[] bytes)
        {
            bytes = Array.Empty<byte>();
            if (string.IsNullOrEmpty(value))
            {
                return false;
            }

            string padded = value.Replace('-', '+').Replace('_', '/');
            switch (padded.Length % 4)
            {
                case 0:
                    break;
                case 2:
                    padded += "==";
                    break;
                case 3:
                    padded += "=";
                    break;
                default:
                    return false;
            }

            try
            {
                bytes = Convert.FromBase64String(padded);
                return true;
            }
            catch (FormatException)
            {
                return false;
            }
        }

        private static bool AudienceContains(JwtJsonObject payload, string expected)
        {
            if (payload.TryGetString("aud", out string single))
            {
                return single == expected;
            }

            if (!payload.TryGetStringArray("aud", out IReadOnlyList<string> values))
            {
                return false;
            }

            for (int i = 0; i < values.Count; i++)
            {
                if (values[i] == expected)
                {
                    return true;
                }
            }

            return false;
        }
    }
}
