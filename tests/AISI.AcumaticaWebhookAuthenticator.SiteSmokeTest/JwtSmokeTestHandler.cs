// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Configuration;

namespace AISI.AcumaticaWebhookAuthenticator.SiteSmokeTest
{
    /// <summary>Bearer JWT: HS256, required <c>bh</c> body hash and <c>aud</c> = webhook registration id.</summary>
    public class JwtSmokeTestHandler : SmokeTestHandlerBase
    {
        /// <summary>Creates the handler.</summary>
        public JwtSmokeTestHandler()
            : base("JWT")
        {
        }

        /// <inheritdoc/>
        protected override IWebhookAuthenticator CreateAuthenticator(IWebhookSecretProvider secretProvider) =>
            new JwtAuthenticator(WebhookAuthPresets.JwtBearer(secretProvider));
    }
}
