// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Configuration;

namespace AISI.AcumaticaWebhookAuthenticator.Acumatica
{
    /// <summary>Wraps the scheme authenticator with per-request policy (e.g. IP allowlist).</summary>
    public interface IAuthenticatorRefiner
    {
        /// <summary>Applies current policy around <paramref name="inner"/>.</summary>
        IWebhookAuthenticator Refine(IWebhookAuthenticator inner);
    }
}
