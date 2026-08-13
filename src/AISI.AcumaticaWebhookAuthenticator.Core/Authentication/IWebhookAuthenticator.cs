// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

namespace AISI.AcumaticaWebhookAuthenticator.Authentication
{
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
