// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Configuration;

namespace AISI.AcumaticaWebhookAuthenticator.SiteSmokeTest
{
    /// <summary>
    /// BASIC scheme, to exercise the <c>WWW-Authenticate</c> challenge on the 401 path. The stored
    /// secret is the whole <c>user:password</c> string.
    /// </summary>
    public class BasicSmokeTestHandler : SmokeTestHandlerBase
    {
        /// <summary>Creates the handler.</summary>
        public BasicSmokeTestHandler()
            : base("BASIC")
        {
        }

        /// <inheritdoc/>
        protected override IWebhookAuthenticator CreateAuthenticator(IWebhookSecretProvider secretProvider) =>
            new BasicAuthenticator(secretProvider, realm: "smoke-test");
    }
}
