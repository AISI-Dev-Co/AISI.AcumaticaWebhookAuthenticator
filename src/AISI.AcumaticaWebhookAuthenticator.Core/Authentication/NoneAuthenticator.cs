// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;

namespace AISI.AcumaticaWebhookAuthenticator.Authentication
{
    /// <summary>
    /// The <c>NONE</c> scheme: every request authenticates.
    /// </summary>
    /// <remarks>
    /// Exists so that "no authentication" is a decision somebody wrote down — visible in
    /// configuration and traces — rather than the silent result of not wiring an authenticator up.
    /// An endpoint using it accepts any payload from anyone who discovers the URL. It consumes no
    /// secret, so unlike every other scheme there is nothing to fail closed on.
    /// </remarks>
    public sealed class NoneAuthenticator : IWebhookAuthenticator
    {
        private NoneAuthenticator()
        {
        }

        /// <summary>The single instance. The type is stateless.</summary>
        public static NoneAuthenticator Instance { get; } = new NoneAuthenticator();

        /// <inheritdoc/>
        public string Code => "NONE";

        /// <inheritdoc/>
        public AuthResult Authenticate(WebhookAuthContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return AuthResult.Success();
        }
    }
}
