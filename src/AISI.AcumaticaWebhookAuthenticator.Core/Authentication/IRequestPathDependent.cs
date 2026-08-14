// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

namespace AISI.AcumaticaWebhookAuthenticator.Authentication
{
    /// <summary>
    /// An authenticator that may depend on the request path, which not every host can supply.
    /// </summary>
    /// <remarks>
    /// Acumatica's <c>WebhookRequest</c> exposes no path, so a configuration that signs
    /// <c>{path}</c> could never verify a single request there. A host that cannot supply a path
    /// checks this capability at handler construction and rejects the configuration loudly, once —
    /// instead of every request failing at runtime as an apparent sender problem. Decorators
    /// forward their inner authenticator's answer, so wrapping a scheme never hides the
    /// dependency.
    /// </remarks>
    public interface IRequestPathDependent
    {
        /// <summary>
        /// Whether this configuration needs <see cref="WebhookAuthContext.Path"/> to verify a
        /// request at all.
        /// </summary>
        bool RequiresRequestPath { get; }
    }
}
