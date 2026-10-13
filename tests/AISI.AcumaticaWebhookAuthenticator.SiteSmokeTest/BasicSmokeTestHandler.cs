// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Configuration;

namespace AISI.AcumaticaWebhookAuthenticator.SiteSmokeTest
{
    /// <summary>Smoke-tests the BASIC scheme, including its <c>WWW-Authenticate</c> challenge on the 401 path.</summary>
    public class BasicSmokeTestHandler : SmokeTestHandlerBase
    {
        public BasicSmokeTestHandler()
            : base("BASIC")
        {
        }

        // BASIC compares against the whole stored secret, so enter it on AS301000 as user:password.
        protected override IWebhookAuthenticator CreateAuthenticator(IWebhookSecretProvider secretProvider) =>
            new BasicAuthenticator(secretProvider, realm: "smoke-test");
    }
}
