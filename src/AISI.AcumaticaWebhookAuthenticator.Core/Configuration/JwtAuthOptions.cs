// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using AISI.AcumaticaWebhookAuthenticator.Signing;

namespace AISI.AcumaticaWebhookAuthenticator.Configuration
{
    /// <summary>Builder for HMAC-signed JWT verification (HS256 / HS512). Snapshot it into <see cref="Authentication.JwtAuthenticator"/> and stop mutating it.</summary>
    public sealed class JwtAuthOptions
    {
        /// <summary>Creates options for an <c>Authorization: Bearer</c> JWT.</summary>
        public JwtAuthOptions(IWebhookSecretProvider secretProvider, string tokenHeader = "Authorization")
        {
            if (string.IsNullOrWhiteSpace(tokenHeader))
            {
                throw new ArgumentException("A token header name is required.", nameof(tokenHeader));
            }

            SecretProvider = secretProvider ?? throw new ArgumentNullException(nameof(secretProvider));
            TokenHeader = tokenHeader;
        }

        /// <summary>Where the HMAC key comes from — the stored secret, UTF-8.</summary>
        public IWebhookSecretProvider SecretProvider { get; }

        /// <summary>Header carrying the JWT.</summary>
        public string TokenHeader { get; }

        /// <summary>Prefix before the compact JWT, or null when the header is the token itself. Defaults to <c>Bearer </c>.</summary>
        public string? SchemePrefix { get; set; } = "Bearer ";

        /// <summary>HMAC algorithm. Defaults to SHA-256 (JWT <c>HS256</c>). SHA-1 is rejected.</summary>
        public HmacAlgorithm Algorithm { get; set; } = HmacAlgorithm.Sha256;

        /// <summary>Required <c>iss</c>, or null to skip issuer checks.</summary>
        public string? Issuer { get; set; }

        /// <summary>Required <c>aud</c> (string or array member), or null to skip audience checks.</summary>
        public string? Audience { get; set; }

        /// <summary>Leeway for <c>exp</c> / <c>nbf</c>. Defaults to 60 seconds.</summary>
        public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(60);

        /// <summary>When true (the default), a payload without <c>exp</c> is rejected.</summary>
        public bool RequireExpiration { get; set; } = true;

        /// <summary>A developer-facing reason this configuration cannot work, or null.</summary>
        public string? DescribeMisconfiguration()
        {
            if (!Enum.IsDefined(typeof(HmacAlgorithm), Algorithm))
            {
                return FormattableString.Invariant($"'{Algorithm}' is not a known HMAC algorithm.");
            }

            if (Algorithm == HmacAlgorithm.Sha1)
            {
                return "JWT HMAC does not include HS1; use Sha256 (HS256) or Sha512 (HS512).";
            }

            if (ClockSkew < TimeSpan.Zero)
            {
                return "Clock skew cannot be negative.";
            }

            return null;
        }

        /// <summary>JWT <c>alg</c> name for <see cref="Algorithm"/>, or null when the algorithm is not a JWT HMAC.</summary>
        public string? JwtAlgorithmName
        {
            get
            {
                switch (Algorithm)
                {
                    case HmacAlgorithm.Sha256:
                        return "HS256";
                    case HmacAlgorithm.Sha512:
                        return "HS512";
                    default:
                        return null;
                }
            }
        }
    }
}
