// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;

namespace AISI.AcumaticaWebhookAuthenticator.Authentication
{
    /// <summary>
    /// The <c>NONE</c> scheme: every request authenticates.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This exists so that "no authentication" is a decision somebody wrote down — an explicit
    /// scheme recorded against the endpoint, visible in configuration and in traces — rather than
    /// the silent result of not wiring an authenticator up. An endpoint using it accepts any
    /// payload from anyone who discovers the URL, which is trivially discoverable in transit.
    /// Reserve it for development and for senders that genuinely sign nothing, and treat the
    /// payload as untrusted input either way.
    /// </para>
    /// <para>
    /// It deliberately does not fail closed on a missing secret the way every other scheme does,
    /// because it consumes no secret. There is nothing to misconfigure and nothing to rotate.
    /// </para>
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
