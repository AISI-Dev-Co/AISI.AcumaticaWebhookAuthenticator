// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using AISI.AcumaticaWebhookAuthenticator.Diagnostics;
using AISI.AcumaticaWebhookAuthenticator.Signing;

namespace AISI.AcumaticaWebhookAuthenticator.Authentication
{
    /// <summary>The <c>JWT</c> scheme: an HS256/HS512 compact JWS in a header; the body is bound only through the <c>bh</c> claim.</summary>
    public sealed class JwtAuthenticator : IWebhookAuthenticator, IChallengeSource
    {
        // Throws on invalid bytes: replacement decoding would let a malformed segment parse.
        private static readonly Encoding Utf8Strict = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

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
            _schemePrefix = string.IsNullOrEmpty(options.SchemePrefix) ? null : options.SchemePrefix;
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

        /// <summary>RFC 6750-style <c>WWW-Authenticate</c> value for a 401.</summary>
        public string Challenge { get; }

        /// <inheritdoc/>
        public AuthResult Authenticate(WebhookAuthContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

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
            foreach (string headerValue in headerValues)
            {
                if (!TryExtractToken(headerValue, out string compact))
                {
                    continue;
                }

                AuthResult result = AuthenticateToken(compact, secret, context);
                if (result.Succeeded)
                {
                    return result;
                }

                firstFailure ??= result;
            }

            return firstFailure ?? AuthResult.Fail(AuthFailureCode.CredentialMalformed);
        }

        internal static byte[] ComputeBodyHash(byte[] body)
        {
            using (SHA256 sha = SHA256.Create())
            {
                return sha.ComputeHash(body);
            }
        }

        private bool TryExtractToken(string headerValue, out string token)
        {
            if (_schemePrefix is null)
            {
                token = headerValue.Trim();
                return token.Length > 0;
            }

            return CredentialVerifier.TryStripScheme(headerValue, _schemePrefix, out token);
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

            JwtJsonObject? header = DecodeJson(headerSegment);
            if (header is null)
            {
                return AuthResult.Fail(AuthFailureCode.JwtMalformed);
            }

            if (header.Contains("crit"))
            {
                // RFC 7515 §4.1.11: we understand no crit extensions, so any crit MUST reject.
                return AuthResult.Fail(AuthFailureCode.JwtCriticalHeader);
            }

            if (!header.TryGetString("alg", out string alg) ||
                !string.Equals(alg, _jwtAlg, StringComparison.Ordinal))
            {
                return AuthResult.Fail(AuthFailureCode.JwtAlgorithmRejected);
            }

            if (!TryBase64UrlDecode(signatureSegment, out byte[] signature))
            {
                return AuthResult.Fail(AuthFailureCode.JwtMalformed);
            }

            byte[] signingInput = Encoding.ASCII.GetBytes(compact.Substring(0, secondDot));
            if (!secret.Matches(_algorithm, signingInput, signature, context.ReceivedOn))
            {
                return AuthResult.Fail(AuthFailureCode.SignatureMismatch);
            }

            JwtJsonObject? payload = DecodeJson(payloadSegment);
            if (payload is null)
            {
                return AuthResult.Fail(AuthFailureCode.JwtMalformed);
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
            else if (_requireExpiration)
            {
                return AuthResult.Fail(AuthFailureCode.JwtExpirationMissing);
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

            if (!AudienceAccepted(payload, context))
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

        private bool AudienceAccepted(JwtJsonObject payload, WebhookAuthContext context)
        {
            if (_audience is object)
            {
                return AudienceContains(payload, _audience);
            }

            if (!_bindAudienceToWebhookId)
            {
                return true;
            }

            // No webhook id means nothing to bind to: fail closed rather than accept "aud":"".
            return context.WebhookId is Guid id && AudienceContains(payload, id.ToString("D"));
        }

        private static string BuildChallenge(string tokenHeader, string? schemePrefix)
        {
            string scheme;
            if (schemePrefix is object)
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

            if (scheme.Length == 0)
            {
                scheme = "Bearer";
            }

            return scheme + " realm=\"webhook\"";
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

        private static JwtJsonObject? DecodeJson(string segment)
        {
            if (!TryBase64UrlDecode(segment, out byte[] bytes))
            {
                return null;
            }

            string json;
            try
            {
                json = Utf8Strict.GetString(bytes);
            }
            catch (DecoderFallbackException)
            {
                return null;
            }

            return JwtJsonObject.TryParse(json, out JwtJsonObject parsed) ? parsed : null;
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
