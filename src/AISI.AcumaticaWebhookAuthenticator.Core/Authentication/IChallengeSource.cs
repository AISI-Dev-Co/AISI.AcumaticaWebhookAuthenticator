// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

namespace AISI.AcumaticaWebhookAuthenticator.Authentication
{
    /// <summary>Optional <c>WWW-Authenticate</c> challenge on 401.</summary>
    public interface IChallengeSource
    {
        /// <summary>Header value, or null when the inner scheme has none.</summary>
        string? Challenge { get; }
    }
}
