// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Signing;

namespace AISI.AcumaticaWebhookAuthenticator.Configuration
{
    /// <summary>Settings for <see cref="JwtAuthenticator"/>, copied at construction; later changes have no effect.</summary>
    public sealed class JwtAuthOptions
    {
        // The claim's value is the base64url SHA-256 of the raw HTTP body.
        public const string BodyHashClaimName = "bh";

        public const int DefaultMaxTokenLength = 8192;

        internal const int MinTokenLength = 32;

        public static readonly TimeSpan MaxClockSkew = TimeSpan.FromHours(1);

        public JwtAuthOptions(IWebhookSecretProvider secretProvider, string tokenHeader = "Authorization")
        {
            if (string.IsNullOrWhiteSpace(tokenHeader))
            {
                throw new ArgumentException("A token header name is required.", nameof(tokenHeader));
            }

            SecretProvider = secretProvider ?? throw new ArgumentNullException(nameof(secretProvider));
            TokenHeader = tokenHeader;
        }

        public IWebhookSecretProvider SecretProvider { get; }

        public string TokenHeader { get; }

        // Matched case-insensitively; null means the header value is the token itself.
        public string? SchemePrefix { get; set; } = "Bearer ";

        public HmacAlgorithm Algorithm { get; set; } = HmacAlgorithm.Sha256;

        // Null skips the issuer check entirely.
        public string? Issuer { get; set; }

        // An explicit audience wins over BindAudienceToWebhookId, which otherwise requires aud to contain the webhook registration id.
        public string? Audience { get; set; }

        public bool BindAudienceToWebhookId { get; set; } = true;

        public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(60);

        public bool RequireExpiration { get; set; } = true;

        // A present bh claim is always verified; this only decides whether its absence is rejected.
        public bool RequireBodyHash { get; set; } = true;

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

        /// <summary>A developer-facing reason this configuration cannot work, or null when it is coherent.</summary>
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
