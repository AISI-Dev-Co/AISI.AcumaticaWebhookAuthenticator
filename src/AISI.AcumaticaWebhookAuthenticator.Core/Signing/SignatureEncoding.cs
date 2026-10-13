// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

namespace AISI.AcumaticaWebhookAuthenticator.Signing
{
    /// <summary>Wire encoding a sender uses to represent a signature digest in a header value.</summary>
    public enum SignatureEncoding
    {
        Hex = 0,

        Base64 = 1,
    }
}
