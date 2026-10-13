// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using AISI.AcumaticaWebhookAuthenticator.Authentication;

namespace AISI.AcumaticaWebhookAuthenticator.Acumatica
{
    /// <summary>Wraps the scheme authenticator with per-request policy such as an IP allowlist.</summary>
    public interface IAuthenticatorRefiner
    {
        /// <summary>Returns <paramref name="inner"/> wrapped in the policy currently in force.</summary>
        IWebhookAuthenticator Refine(IWebhookAuthenticator inner);
    }
}
