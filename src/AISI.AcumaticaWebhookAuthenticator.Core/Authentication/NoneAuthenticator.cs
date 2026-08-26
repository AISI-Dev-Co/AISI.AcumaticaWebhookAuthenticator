// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;

namespace AISI.AcumaticaWebhookAuthenticator.Authentication
{
    /// <summary>Every request authenticates. Use only as an explicit, recorded decision.</summary>
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
