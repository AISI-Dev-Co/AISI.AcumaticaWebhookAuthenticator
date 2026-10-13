// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Configuration;

namespace AISI.AcumaticaWebhookAuthenticator.SiteSmokeTest
{
    /// <summary>Smoke-tests the HS256 Bearer JWT preset, which requires a <c>bh</c> body hash and an <c>aud</c> equal to the webhook id.</summary>
    public class JwtSmokeTestHandler : SmokeTestHandlerBase
    {
        public JwtSmokeTestHandler()
            : base("JWT")
        {
        }

        protected override IWebhookAuthenticator CreateAuthenticator(IWebhookSecretProvider secretProvider) =>
            new JwtAuthenticator(WebhookAuthPresets.JwtBearer(secretProvider));
    }
}
