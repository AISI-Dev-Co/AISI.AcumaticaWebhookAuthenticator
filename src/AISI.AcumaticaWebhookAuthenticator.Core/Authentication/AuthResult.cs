// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

namespace AISI.AcumaticaWebhookAuthenticator.Authentication
{
    /// <summary>
    /// The outcome of an authentication attempt.
    /// </summary>
    /// <remarks>
    /// <see cref="FailureCode"/> is diagnostic only. Callers must not vary the HTTP response by it:
    /// every failure is the same 401 with the same body. See
    /// <see cref="Diagnostics.AuthFailureCode"/>.
    /// </remarks>
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

        /// <summary>
        /// An <see cref="Diagnostics.AuthFailureCode"/> value when it did not, otherwise empty.
        /// Never empty-versus-null: a default-constructed result reports an unspecified failure
        /// rather than a null string.
        /// </summary>
        public string FailureCode => _failureCode ?? Diagnostics.AuthFailureCode.Unspecified;

        /// <summary>Creates a successful result.</summary>
        /// <returns>The result.</returns>
        public static AuthResult Success() => new AuthResult(true, string.Empty);

        /// <summary>Creates a failed result.</summary>
        /// <param name="failureCode">An <see cref="Diagnostics.AuthFailureCode"/> value.</param>
        /// <returns>The result.</returns>
        public static AuthResult Fail(string failureCode) => new AuthResult(false, failureCode);
    }
}
