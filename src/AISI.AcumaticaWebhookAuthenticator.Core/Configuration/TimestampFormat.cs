// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

namespace AISI.AcumaticaWebhookAuthenticator.Configuration
{
    /// <summary>
    /// Wire format of a signed timestamp.
    /// </summary>
    public enum TimestampFormat
    {
        /// <summary>Seconds since the Unix epoch. Stripe and most others.</summary>
        UnixSeconds = 0,

        /// <summary>Milliseconds since the Unix epoch.</summary>
        UnixMilliseconds = 1,

        /// <summary>An ISO 8601 / RFC 3339 instant.</summary>
        Iso8601 = 2,
    }
}
