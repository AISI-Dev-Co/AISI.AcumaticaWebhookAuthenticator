// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

namespace AISI.AcumaticaWebhookAuthenticator.Authentication
{
    /// <summary>
    /// An authenticator whose scheme defines a <c>WWW-Authenticate</c> challenge to send with a
    /// 401.
    /// </summary>
    /// <remarks>
    /// A separate optional interface so <see cref="IWebhookAuthenticator"/> stays minimal: most
    /// schemes have no challenge. A host asks for the capability instead of knowing which concrete
    /// schemes carry one, and a decorator such as <see cref="IpAllowlistAuthenticator"/> forwards
    /// its inner authenticator's — so wrapping a scheme never silently drops its challenge.
    /// </remarks>
    public interface IChallengeSource
    {
        /// <summary>
        /// The <c>WWW-Authenticate</c> value to send with a 401, or <see langword="null"/> when
        /// there is none (a decorator over a challenge-less scheme).
        /// </summary>
        string? Challenge { get; }
    }
}
