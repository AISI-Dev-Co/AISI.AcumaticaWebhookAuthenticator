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
        private AuthResult(bool succeeded, string failureCode)
        {
            Succeeded = succeeded;
            FailureCode = failureCode;
        }

        /// <summary>Whether the request authenticated.</summary>
        public bool Succeeded { get; }

        /// <summary>An <see cref="Diagnostics.AuthFailureCode"/> value when it did not, otherwise empty.</summary>
        public string FailureCode { get; }

        /// <summary>Creates a successful result.</summary>
        /// <returns>The result.</returns>
        public static AuthResult Success() => new AuthResult(true, string.Empty);

        /// <summary>Creates a failed result.</summary>
        /// <param name="failureCode">An <see cref="Diagnostics.AuthFailureCode"/> value.</param>
        /// <returns>The result.</returns>
        public static AuthResult Fail(string failureCode) => new AuthResult(false, failureCode);
    }

    /// <summary>
    /// A strategy for authenticating an inbound webhook request.
    /// </summary>
    public interface IWebhookAuthenticator
    {
        /// <summary>
        /// Short stable identifier for the scheme, e.g. "HMAC". Recorded against the endpoint
        /// configuration and in traces.
        /// </summary>
        string Code { get; }

        /// <summary>
        /// Authenticates a request.
        /// </summary>
        /// <param name="context">The request.</param>
        /// <returns>The outcome.</returns>
        AuthResult Authenticate(WebhookAuthContext context);
    }
}
