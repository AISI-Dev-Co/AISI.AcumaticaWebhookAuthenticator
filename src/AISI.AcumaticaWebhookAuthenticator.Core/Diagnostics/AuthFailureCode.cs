// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

namespace AISI.AcumaticaWebhookAuthenticator.Diagnostics
{
    /// <summary>
    /// Why an authentication attempt failed.
    /// </summary>
    /// <remarks>
    /// These codes are for the trace and for tests. They must never reach the sender. Every
    /// authentication failure returns the same 401 with the same generic body, because telling a
    /// caller whether the signature was malformed, absent, or merely wrong hands them a decision
    /// oracle they can iterate against.
    /// </remarks>
    public static class AuthFailureCode
    {
        #region Signature
        /// <summary>The configured signature header was not present on the request.</summary>
        public const string SignatureHeaderMissing = "signature_header_missing";

        /// <summary>The signature header was present but the configured element could not be found inside it.</summary>
        public const string SignatureElementMissing = "signature_element_missing";

        /// <summary>The signature did not carry the configured prefix, e.g. "sha256=".</summary>
        public const string SignaturePrefixMismatch = "signature_prefix_mismatch";

        /// <summary>The signature was not valid hex or base64.</summary>
        public const string SignatureMalformed = "signature_malformed";

        /// <summary>The signature was well formed but did not match any candidate secret.</summary>
        public const string SignatureMismatch = "signature_mismatch";
        #endregion

        #region Timestamp
        /// <summary>The scheme requires a timestamp and none was present.</summary>
        public const string TimestampMissing = "timestamp_missing";

        /// <summary>The timestamp was present but could not be parsed in the configured format.</summary>
        public const string TimestampMalformed = "timestamp_malformed";

        /// <summary>The timestamp fell outside the configured replay tolerance, in either direction.</summary>
        public const string TimestampOutsideTolerance = "timestamp_outside_tolerance";
        #endregion

        #region Template
        /// <summary>The template referenced a header that the request did not carry.</summary>
        public const string TemplateHeaderMissing = "template_header_missing";

        /// <summary>The template referenced {method} but the platform did not surface one.</summary>
        public const string TemplateMethodUnavailable = "template_method_unavailable";

        /// <summary>The template referenced {path} but the platform did not surface one.</summary>
        public const string TemplatePathUnavailable = "template_path_unavailable";

        /// <summary>The template could not be resolved for a reason not covered above.</summary>
        public const string TemplateInvalid = "template_invalid";
        #endregion

        #region Credential
        /// <summary>The header carrying the credential was not present on the request. Reported by the SECRET and BASIC schemes.</summary>
        public const string CredentialMissing = "credential_missing";

        /// <summary>The credential was present but not in the expected shape: wrong authorization scheme, invalid base64, or a missing prefix.</summary>
        public const string CredentialMalformed = "credential_malformed";

        /// <summary>The credential was well formed but did not match any live secret.</summary>
        public const string CredentialMismatch = "credential_mismatch";
        #endregion

        #region Client address
        /// <summary>The configured client-address header was not present on the request.</summary>
        public const string ClientAddressMissing = "client_address_missing";

        /// <summary>The client-address header was present but no address could be read at the trusted depth.</summary>
        public const string ClientAddressMalformed = "client_address_malformed";

        /// <summary>The client address was read but is not on the allowlist.</summary>
        public const string ClientAddressDenied = "client_address_denied";
        #endregion

        #region Secret and configuration
        /// <summary>The secret provider returned nothing, so the endpoint has no secret configured.</summary>
        public const string SecretUnavailable = "secret_unavailable";

        /// <summary>
        /// The configuration itself is incoherent and no request could verify against it. Only
        /// <see cref="WebhookSignatureTester"/> reports this; on the request path the same condition
        /// is an exception thrown when the authenticator is constructed.
        /// </summary>
        public const string Misconfigured = "misconfigured";

        /// <summary>
        /// A failure with no more specific code. Reported by a default-constructed
        /// <see cref="Authentication.AuthResult"/>, which no code path should produce.
        /// </summary>
        public const string Unspecified = "unspecified";
        #endregion
    }
}
