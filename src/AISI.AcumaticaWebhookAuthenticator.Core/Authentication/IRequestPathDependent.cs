// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

namespace AISI.AcumaticaWebhookAuthenticator.Authentication
{
    /// <summary>True when the scheme signs <c>{path}</c>. Acumatica cannot supply a path.</summary>
    public interface IRequestPathDependent
    {
        /// <summary>Whether <see cref="WebhookAuthContext.Path"/> is required to verify anything.</summary>
        bool RequiresRequestPath { get; }
    }
}
