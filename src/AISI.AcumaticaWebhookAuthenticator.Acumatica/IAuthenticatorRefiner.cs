// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Configuration;

namespace AISI.AcumaticaWebhookAuthenticator.Acumatica
{
    /// <summary>
    /// A secret provider that also carries per-request authentication policy, applied by wrapping
    /// the authenticator on every request.
    /// </summary>
    /// <remarks>
    /// <see cref="AuthenticatedWebhookHandlerBase"/> asks its <see cref="IWebhookSecretProvider"/>
    /// for this capability instead of knowing which concrete provider stores policy — so a
    /// decorated or replacement provider keeps the administrator's restrictions by forwarding one
    /// method instead of silently dropping them (a fail-open outcome).
    /// </remarks>
    public interface IAuthenticatorRefiner
    {
        /// <summary>
        /// Applies the provider's current policy around <paramref name="inner"/>, per request.
        /// </summary>
        /// <param name="inner">The authenticator the handler constructed.</param>
        IWebhookAuthenticator Refine(IWebhookAuthenticator inner);
    }
}
