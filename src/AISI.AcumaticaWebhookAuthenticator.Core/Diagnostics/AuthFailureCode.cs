// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

namespace AISI.AcumaticaWebhookAuthenticator.Diagnostics
{
    /// <summary>Trace and test codes for a failed attempt, never to be sent to the caller.</summary>
    public static class AuthFailureCode
    {
        #region Signature
        public const string SignatureHeaderMissing = "signature_header_missing";

        public const string SignatureElementMissing = "signature_element_missing";

        public const string SignaturePrefixMismatch = "signature_prefix_mismatch";

        public const string SignatureMalformed = "signature_malformed";

        public const string SignatureMismatch = "signature_mismatch";
        #endregion

        #region Timestamp
        public const string TimestampMissing = "timestamp_missing";

        public const string TimestampMalformed = "timestamp_malformed";

        public const string TimestampOutsideTolerance = "timestamp_outside_tolerance";
        #endregion

        #region Template
        public const string TemplateHeaderMissing = "template_header_missing";

        /// <summary>The template referenced {method} but the platform did not surface one.</summary>
        public const string TemplateMethodUnavailable = "template_method_unavailable";

        /// <summary>The template referenced {path} but the platform did not surface one.</summary>
        public const string TemplatePathUnavailable = "template_path_unavailable";
        #endregion

        #region Credential
        public const string CredentialMissing = "credential_missing";

        /// <summary>The credential was present but had the wrong authorization scheme, invalid base64, or a missing prefix.</summary>
        public const string CredentialMalformed = "credential_malformed";

        public const string CredentialMismatch = "credential_mismatch";
        #endregion

        #region JWT
        public const string JwtMalformed = "jwt_malformed";

        /// <summary>The header <c>alg</c> was missing, <c>none</c>, or not the configured HMAC.</summary>
        public const string JwtAlgorithmRejected = "jwt_algorithm_rejected";

        public const string JwtExpirationMissing = "jwt_expiration_missing";

        public const string JwtExpired = "jwt_expired";

        public const string JwtNotYetValid = "jwt_not_yet_valid";

        public const string JwtIssuerMismatch = "jwt_issuer_mismatch";

        public const string JwtAudienceMismatch = "jwt_audience_mismatch";

        /// <summary>The header carried <c>crit</c>, which RFC 7515 requires rejecting since this verifier understands no extensions.</summary>
        public const string JwtCriticalHeader = "jwt_critical_header";

        public const string JwtBodyHashMissing = "jwt_body_hash_missing";

        public const string JwtBodyHashMismatch = "jwt_body_hash_mismatch";
        #endregion

        #region Client address
        public const string ClientAddressMissing = "client_address_missing";

        /// <summary>The client-address header was present but no address could be read at the trusted depth.</summary>
        public const string ClientAddressMalformed = "client_address_malformed";

        public const string ClientAddressDenied = "client_address_denied";
        #endregion

        #region Secret and configuration
        public const string SecretUnavailable = "secret_unavailable";

        /// <summary>The configuration can never verify a request, as reported by <see cref="WebhookSignatureTester"/> or a host that denies everything for an unusable stored setting.</summary>
        public const string Misconfigured = "misconfigured";
        #endregion

        #region Fallback
        /// <summary>No more specific code applies, as for a default <see cref="Authentication.AuthResult"/> or an authenticator that threw.</summary>
        public const string Unspecified = "unspecified";
        #endregion
    }
}
