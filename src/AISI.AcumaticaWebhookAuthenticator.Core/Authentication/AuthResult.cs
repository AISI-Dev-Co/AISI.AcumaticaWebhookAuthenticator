// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using AISI.AcumaticaWebhookAuthenticator.Diagnostics;

namespace AISI.AcumaticaWebhookAuthenticator.Authentication
{
    /// <summary>Authentication outcome whose <see cref="FailureCode"/> is for traces, never HTTP responses.</summary>
    public readonly struct AuthResult
    {
        private readonly string? _failureCode;

        private AuthResult(bool succeeded, string failureCode)
        {
            Succeeded = succeeded;
            _failureCode = failureCode;
        }

        public bool Succeeded { get; }

        // A default(AuthResult) is a failure with no code, so it must still report one.
        public string FailureCode => _failureCode ?? AuthFailureCode.Unspecified;

        public static AuthResult Success() => new AuthResult(true, string.Empty);

        public static AuthResult Fail(string failureCode) =>
            new AuthResult(false, string.IsNullOrEmpty(failureCode) ? AuthFailureCode.Unspecified : failureCode);
    }
}
