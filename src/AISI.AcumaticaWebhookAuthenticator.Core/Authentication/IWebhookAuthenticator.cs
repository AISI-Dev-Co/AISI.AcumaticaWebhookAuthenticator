// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

namespace AISI.AcumaticaWebhookAuthenticator.Authentication
{
    /// <summary>
    /// A strategy for authenticating an inbound webhook request.
    /// </summary>
    public interface IWebhookAuthenticator
    {
        /// <summary>Short scheme id, e.g. HMAC, JWT, BASIC.</summary>
        string Code { get; }

        /// <summary>Authenticates one request.</summary>
        AuthResult Authenticate(WebhookAuthContext context);
    }
}
