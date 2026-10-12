// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using AISI.AcumaticaWebhookAuthenticator.Diagnostics;

namespace AISI.AcumaticaWebhookAuthenticator.Authentication
{
    /// <summary>Authentication outcome. <see cref="FailureCode"/> is for traces, not HTTP responses.</summary>
    public readonly struct AuthResult
    {
        private readonly string? _failureCode;

        private AuthResult(bool succeeded, string failureCode)
        {
            Succeeded = succeeded;
            _failureCode = failureCode;
        }

        /// <summary>Whether the request authenticated.</summary>
        public bool Succeeded { get; }

        /// <summary>An <see cref="AuthFailureCode"/> value on failure (never empty), otherwise empty.</summary>
        public string FailureCode => _failureCode ?? AuthFailureCode.Unspecified;

        /// <summary>Creates a successful result.</summary>
        public static AuthResult Success() => new AuthResult(true, string.Empty);

        /// <summary>Creates a failed result; a blank code becomes <see cref="AuthFailureCode.Unspecified"/>.</summary>
        public static AuthResult Fail(string failureCode) =>
            new AuthResult(false, string.IsNullOrEmpty(failureCode) ? AuthFailureCode.Unspecified : failureCode);
    }
}
