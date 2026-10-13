// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

namespace AISI.AcumaticaWebhookAuthenticator.Configuration
{
    /// <summary>Wire format of a signed timestamp.</summary>
    public enum TimestampFormat
    {
        UnixSeconds = 0,

        UnixMilliseconds = 1,

        Iso8601 = 2,
    }
}
