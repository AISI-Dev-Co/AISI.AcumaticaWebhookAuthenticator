// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

namespace AISI.AcumaticaWebhookAuthenticator.Configuration
{
    /// <summary>
    /// Supplies the signing secret for an endpoint.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The interface exists so that secret storage is a deployment decision rather than a library
    /// one. The intended production implementation reads a <c>[PXRSACryptString]</c> field from the
    /// ERP database, which is Acumatica's own pattern for third-party integration credentials: it is
    /// encrypted at rest, editable by an administrator without a redeployment, unaffected by the
    /// platform's move off .NET Framework because it is an ORM concern rather than a configuration
    /// file one, and it is the only option that works on SaaS, where there is no file system and no
    /// environment to read.
    /// </para>
    /// <para>
    /// Implementations are called once per request and should cache accordingly. They must be safe
    /// to call from multiple threads.
    /// </para>
    /// </remarks>
    public interface IWebhookSecretProvider
    {
        /// <summary>
        /// Returns the secret to verify against, or <see langword="null"/> when none is configured.
        /// A null return denies the request; it never falls back to unauthenticated handling.
        /// </summary>
        /// <returns>The secret, or <see langword="null"/>.</returns>
        WebhookSecret? GetSecret();
    }
}
