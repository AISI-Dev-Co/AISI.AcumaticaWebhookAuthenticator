// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using AISI.AcumaticaWebhookAuthenticator.Signing;

namespace AISI.AcumaticaWebhookAuthenticator.Configuration
{
    /// <summary>
    /// Builder for compact JWS verification (HS256 / HS512). Snapshot it into
    /// <see cref="Authentication.JwtAuthenticator"/> and stop mutating it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// JWT HMAC signs the token, not the HTTP body. Without
    /// <see cref="RequireBodyHash"/> this is an unbound bearer credential — the same
    /// class as <c>SECRET</c> / <c>BASIC</c>, not GitHub/Shopify/Stripe body HMAC.
    /// Body binding is a SHA-256 of the raw request bytes in
    /// <see cref="BodyHashClaimName"/>, compared constant-time. Audience defaults to
    /// the webhook registration id so a reused secret cannot cross webhooks.
    /// </para>
    /// <para>
    /// Mutable and not thread-safe. Build it, hand it to an authenticator, and stop
    /// touching it — the authenticator copies what it needs at construction.
    /// </para>
    /// </remarks>
    public sealed class JwtAuthOptions
    {
        /// <summary>
        /// Payload claim carrying the base64url SHA-256 of the raw HTTP body.
        /// </summary>
        public const string BodyHashClaimName = "bh";

        /// <summary>Default compact-token size cap, in characters.</summary>
        public const int DefaultMaxTokenLength = 8192;

        /// <summary>Largest accepted <see cref="ClockSkew"/>; wider windows are rejected at construction.</summary>
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

        /// <summary>Where the JWS HMAC key comes from — the stored secret, UTF-8.</summary>
        public IWebhookSecretProvider SecretProvider { get; }

        /// <summary>Header carrying the JWT.</summary>
        public string TokenHeader { get; }

        /// <summary>Prefix before the compact JWT, or null when the header is the token itself. Defaults to <c>Bearer </c>.</summary>
        public string? SchemePrefix { get; set; } = "Bearer ";

        /// <summary>HMAC algorithm. Defaults to SHA-256 (JWT <c>HS256</c>). SHA-1 is rejected.</summary>
        public HmacAlgorithm Algorithm { get; set; } = HmacAlgorithm.Sha256;

        /// <summary>Required <c>iss</c>, or null to skip issuer checks.</summary>
        public string? Issuer { get; set; }

        /// <summary>
        /// Required <c>aud</c> (string or array member). When null and
        /// <see cref="BindAudienceToWebhookId"/> is true (the default), the webhook
        /// registration id is required instead — iss/aud are not silently off.
        /// </summary>
        public string? Audience { get; set; }

        /// <summary>
        /// When true (the default) and <see cref="Audience"/> is null, require payload
        /// <c>aud</c> to contain the webhook registration id. Turn off only when the
        /// sender cannot mint per-webhook tokens.
        /// </summary>
        public bool BindAudienceToWebhookId { get; set; } = true;

        /// <summary>Leeway for <c>exp</c> / <c>nbf</c>. Defaults to 60 seconds. Capped at <see cref="MaxClockSkew"/>.</summary>
        public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(60);

        /// <summary>When true (the default), a payload without <c>exp</c> is rejected.</summary>
        public bool RequireExpiration { get; set; } = true;

        /// <summary>
        /// When true (the default), require <see cref="BodyHashClaimName"/> and compare it
        /// constant-time to SHA-256 of the raw request body. A present claim is always
        /// verified, even when this is false.
        /// </summary>
        public bool RequireBodyHash { get; set; } = true;

        /// <summary>Maximum compact JWT length in characters. Defaults to <see cref="DefaultMaxTokenLength"/>.</summary>
        public int MaxTokenLength { get; set; } = DefaultMaxTokenLength;

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
                return "Clock skew cannot exceed one hour.";
            }

            if (MaxTokenLength < 32)
            {
                return "The token size cap must be at least 32 characters.";
            }

            if (ContainsHeaderInjection(TokenHeader) ||
                (SchemePrefix is object && ContainsHeaderInjection(SchemePrefix)))
            {
                return "The token header and scheme prefix cannot contain quotes, backslashes or control characters.";
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
    }
}
