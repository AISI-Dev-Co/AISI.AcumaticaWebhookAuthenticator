// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

namespace AISI.AcumaticaWebhookAuthenticator.Authentication
{
    /// <summary>A scheme that may sign <c>{path}</c>, which Acumatica cannot supply.</summary>
    public interface IRequestPathDependent
    {
        /// <summary>Whether <see cref="WebhookAuthContext.Path"/> is required to verify anything.</summary>
        bool RequiresRequestPath { get; }
    }
}
