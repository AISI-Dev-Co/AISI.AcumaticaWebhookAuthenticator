// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;

namespace AISI.AcumaticaWebhookAuthenticator.Authentication
{
    /// <summary>Authenticates every request, so use it only as an explicit, recorded decision.</summary>
    public sealed class NoneAuthenticator : IWebhookAuthenticator
    {
        private NoneAuthenticator()
        {
        }

        public static NoneAuthenticator Instance { get; } = new NoneAuthenticator();

        public string Code => "NONE";

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
