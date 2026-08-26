// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using AISI.AcumaticaWebhookAuthenticator.Diagnostics;
using AISI.AcumaticaWebhookAuthenticator.Signing;

namespace AISI.AcumaticaWebhookAuthenticator.Authentication
{
    /// <summary>The <c>JWT</c> scheme: HMAC-signed compact JWT (HS256 / HS512) in a header.</summary>
    public sealed class JwtAuthenticator : IWebhookAuthenticator, IChallengeSource
    {
        private readonly IWebhookSecretProvider _secretProvider;
        private readonly string _tokenHeader;
        private readonly string? _schemePrefix;
        private readonly HmacAlgorithm _algorithm;
        private readonly string _jwtAlg;
        private readonly string? _issuer;
        private readonly string? _audience;
        private readonly TimeSpan _clockSkew;
        private readonly bool _requireExpiration;

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
            _clockSkew = options.ClockSkew;
            _requireExpiration = options.RequireExpiration;
            Challenge = "Bearer realm=\"webhook\"";
        }

        /// <inheritdoc/>
        public string Code => "JWT";

        /// <summary>RFC 6750 <c>WWW-Authenticate</c> value for a 401.</summary>
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
            bool anyWellFormed = false;

            foreach (string headerValue in headerValues)
            {
                if (!TryExtractToken(headerValue, out string compact))
                {
                    continue;
                }

                anyWellFormed = true;
                AuthResult result = AuthenticateToken(compact, secret, context.ReceivedOn);
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

        private AuthResult AuthenticateToken(string compact, WebhookSecret secret, DateTimeOffset receivedOn)
        {
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

            if (!TryGetJsonString(headerJson, "alg", out string alg) ||
                !string.Equals(alg, _jwtAlg, StringComparison.Ordinal))
            {
                return AuthResult.Fail(AuthFailureCode.JwtAlgorithmRejected);
            }

            if (signatureSegment.Length == 0 ||
                !TryBase64UrlDecode(payloadSegment, out byte[] payloadBytes) ||
                !TryBase64UrlDecode(signatureSegment, out byte[] signature))
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

            byte[] signingInput = Encoding.ASCII.GetBytes(headerSegment + "." + payloadSegment);
            if (!secret.MatchesAny(_algorithm, signingInput, new[] { signature }, receivedOn))
            {
                return AuthResult.Fail(AuthFailureCode.SignatureMismatch);
            }

            if (_requireExpiration && !TryGetJsonNumber(payloadJson, "exp", out _))
            {
                return AuthResult.Fail(AuthFailureCode.JwtExpirationMissing);
            }

            if (TryGetJsonNumber(payloadJson, "exp", out long exp))
            {
                DateTimeOffset expires = DateTimeOffset.FromUnixTimeSeconds(exp).Add(_clockSkew);
                if (receivedOn > expires)
                {
                    return AuthResult.Fail(AuthFailureCode.JwtExpired);
                }
            }

            if (TryGetJsonNumber(payloadJson, "nbf", out long nbf))
            {
                DateTimeOffset notBefore = DateTimeOffset.FromUnixTimeSeconds(nbf).Subtract(_clockSkew);
                if (receivedOn < notBefore)
                {
                    return AuthResult.Fail(AuthFailureCode.JwtNotYetValid);
                }
            }

            if (_issuer is object)
            {
                if (!TryGetJsonString(payloadJson, "iss", out string iss) || iss != _issuer)
                {
                    return AuthResult.Fail(AuthFailureCode.JwtIssuerMismatch);
                }
            }

            if (_audience is object && !AudienceContains(payloadJson, _audience))
            {
                return AuthResult.Fail(AuthFailureCode.JwtAudienceMismatch);
            }

            return AuthResult.Success();
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

        private static bool AudienceContains(string json, string expected)
        {
            if (TryGetJsonString(json, "aud", out string single))
            {
                return single == expected;
            }

            if (!TryGetJsonStringArray(json, "aud", out IReadOnlyList<string> values))
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

        private static bool TryGetJsonNumber(string json, string name, out long value)
        {
            value = 0;
            if (!TryFindKey(json, name, out int colon))
            {
                return false;
            }

            int i = SkipWs(json, colon + 1);
            int start = i;
            if (i < json.Length && json[i] == '-')
            {
                i++;
            }

            if (i >= json.Length || json[i] < '0' || json[i] > '9')
            {
                return false;
            }

            while (i < json.Length && json[i] >= '0' && json[i] <= '9')
            {
                i++;
            }

            return long.TryParse(
                json.Substring(start, i - start),
                NumberStyles.Integer,
                CultureInfo.InvariantCulture,
                out value);
        }

        private static bool TryGetJsonString(string json, string name, out string value)
        {
            value = string.Empty;
            if (!TryFindKey(json, name, out int colon))
            {
                return false;
            }

            int i = SkipWs(json, colon + 1);
            return TryReadJsonString(json, i, out value, out _);
        }

        private static bool TryGetJsonStringArray(string json, string name, out IReadOnlyList<string> values)
        {
            values = Array.Empty<string>();
            if (!TryFindKey(json, name, out int colon))
            {
                return false;
            }

            int i = SkipWs(json, colon + 1);
            if (i >= json.Length || json[i] != '[')
            {
                return false;
            }

            i++;
            var list = new List<string>();
            while (i < json.Length)
            {
                i = SkipWs(json, i);
                if (i < json.Length && json[i] == ']')
                {
                    values = list;
                    return true;
                }

                if (!TryReadJsonString(json, i, out string item, out int after))
                {
                    return false;
                }

                list.Add(item);
                i = SkipWs(json, after);
                if (i < json.Length && json[i] == ',')
                {
                    i++;
                }
            }

            return false;
        }

        private static bool TryFindKey(string json, string name, out int colon)
        {
            colon = -1;
            string needle = "\"" + name + "\"";
            int start = 0;
            while (start < json.Length)
            {
                int at = json.IndexOf(needle, start, StringComparison.Ordinal);
                if (at < 0)
                {
                    return false;
                }

                int after = SkipWs(json, at + needle.Length);
                if (after < json.Length && json[after] == ':')
                {
                    colon = after;
                    return true;
                }

                start = at + 1;
            }

            return false;
        }

        private static bool TryReadJsonString(string json, int index, out string value, out int after)
        {
            value = string.Empty;
            after = index;
            if (index >= json.Length || json[index] != '"')
            {
                return false;
            }

            var builder = new StringBuilder();
            for (int i = index + 1; i < json.Length; i++)
            {
                char c = json[i];
                if (c == '"')
                {
                    value = builder.ToString();
                    after = i + 1;
                    return true;
                }

                if (c == '\\')
                {
                    i++;
                    if (i >= json.Length)
                    {
                        return false;
                    }

                    builder.Append(json[i]);
                    continue;
                }

                builder.Append(c);
            }

            return false;
        }

        private static int SkipWs(string json, int index)
        {
            while (index < json.Length && char.IsWhiteSpace(json[index]))
            {
                index++;
            }

            return index;
        }
    }
}
