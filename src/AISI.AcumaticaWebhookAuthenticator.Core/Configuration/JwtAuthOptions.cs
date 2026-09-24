// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Signing;

namespace AISI.AcumaticaWebhookAuthenticator.Configuration
{
    /// <summary>Settings for <see cref="JwtAuthenticator"/>, copied at construction; later changes have no effect.</summary>
    public sealed class JwtAuthOptions
    {
        /// <summary>Payload claim carrying the base64url SHA-256 of the raw HTTP body.</summary>
        public const string BodyHashClaimName = "bh";

        /// <summary>Default compact-token size cap, in characters.</summary>
        public const int DefaultMaxTokenLength = 8192;

        internal const int MinTokenLength = 32;

        /// <summary>Largest accepted <see cref="ClockSkew"/>.</summary>
        public static readonly TimeSpan MaxClockSkew = TimeSpan.FromHours(1);

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

        /// <summary>Where the JWS HMAC key comes from.</summary>
        public IWebhookSecretProvider SecretProvider { get; }

        /// <summary>Header carrying the JWT.</summary>
        public string TokenHeader { get; }

        /// <summary>Case-insensitive scheme before the token, or null when the header is the token itself. Defaults to <c>Bearer </c>.</summary>
        public string? SchemePrefix { get; set; } = "Bearer ";

        /// <summary>HMAC algorithm. Defaults to SHA-256 (<c>HS256</c>); SHA-1 is rejected.</summary>
        public HmacAlgorithm Algorithm { get; set; } = HmacAlgorithm.Sha256;

        /// <summary>Required <c>iss</c>, or null to skip issuer checks.</summary>
        public string? Issuer { get; set; }

        /// <summary>Required <c>aud</c> (string or array member); overrides <see cref="BindAudienceToWebhookId"/>.</summary>
        public string? Audience { get; set; }

        /// <summary>When true (the default) and <see cref="Audience"/> is null, <c>aud</c> must contain the webhook registration id.</summary>
        public bool BindAudienceToWebhookId { get; set; } = true;

        /// <summary>Leeway for <c>exp</c> / <c>nbf</c>. Defaults to 60 seconds; capped at <see cref="MaxClockSkew"/>.</summary>
        public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(60);

        /// <summary>When true (the default), a payload without <c>exp</c> is rejected.</summary>
        public bool RequireExpiration { get; set; } = true;

        /// <summary>When true (the default), <see cref="BodyHashClaimName"/> is required; a present claim is always verified.</summary>
        public bool RequireBodyHash { get; set; } = true;

        /// <summary>Maximum compact JWT length in characters. Defaults to <see cref="DefaultMaxTokenLength"/>.</summary>
        public int MaxTokenLength { get; set; } = DefaultMaxTokenLength;

        internal string? JwtAlgorithmName
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

        /// <summary>A developer-facing reason this configuration cannot work, or null.</summary>
        public string? DescribeMisconfiguration()
        {
            if (!Enum.IsDefined(typeof(HmacAlgorithm), Algorithm))
            {
                return FormattableString.Invariant($"'{Algorithm}' is not a known HMAC algorithm.");
            }

            if (Algorithm == HmacAlgorithm.Sha1)
            {
                return "JWT JWS does not include HS1; use Sha256 (HS256) or Sha512 (HS512).";
            }

            if (ClockSkew < TimeSpan.Zero)
            {
                return "Clock skew cannot be negative.";
            }

            if (ClockSkew > MaxClockSkew)
            {
                return FormattableString.Invariant($"Clock skew cannot exceed {MaxClockSkew.TotalMinutes} minutes.");
            }

            if (MaxTokenLength < MinTokenLength)
            {
                return FormattableString.Invariant($"The token size cap must be at least {MinTokenLength} characters.");
            }

            if (CredentialVerifier.ContainsHeaderInjection(TokenHeader) ||
                (SchemePrefix is object && CredentialVerifier.ContainsHeaderInjection(SchemePrefix)))
            {
                return "The token header and scheme prefix cannot contain quotes, backslashes or control characters.";
            }

            return null;
        }
    }
}
