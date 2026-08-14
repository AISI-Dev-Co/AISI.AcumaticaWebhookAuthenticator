// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Configuration;

namespace AISI.AcumaticaWebhookAuthenticator.Acumatica
{
    /// <summary>
    /// A secret provider that also carries per-request authentication policy — applied by
    /// wrapping the authenticator on every request.
    /// </summary>
    /// <remarks>
    /// <see cref="AuthenticatedWebhookHandlerBase"/> asks its <see cref="IWebhookSecretProvider"/>
    /// for this capability instead of knowing which concrete provider stores policy, so a
    /// decorated or replacement provider keeps the administrator's restrictions by forwarding one
    /// method — rather than silently dropping them because a type check no longer matched, which
    /// would be a fail-open outcome.
    /// </remarks>
    public interface IAuthenticatorRefiner
    {
        /// <summary>
        /// Applies the provider's current policy around <paramref name="inner"/>. Called per
        /// request, so policy edits take effect on the provider's own cadence.
        /// </summary>
        /// <param name="inner">The authenticator the handler constructed.</param>
        /// <returns><paramref name="inner"/>, wrapped or substituted as the policy requires.</returns>
        IWebhookAuthenticator Refine(IWebhookAuthenticator inner);
    }
}
