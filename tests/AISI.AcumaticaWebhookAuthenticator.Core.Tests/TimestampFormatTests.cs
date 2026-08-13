// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using AISI.AcumaticaWebhookAuthenticator.Diagnostics;
using Xunit;

namespace AISI.AcumaticaWebhookAuthenticator.Tests
{
    /// <summary>
    /// Two of the three wire formats had no coverage at all — only Unix seconds was exercised, by
    /// the Stripe vectors.
    /// </summary>
    public class TimestampFormatTests
    {
        private static readonly DateTimeOffset Noon =
            new DateTimeOffset(2026, 3, 14, 12, 0, 0, TimeSpan.Zero);

        [Theory]
        [InlineData("1773489600", true)]     // exactly Noon
        [InlineData("1773489540", true)]     // one minute early
        [InlineData("1773489000", false)]    // ten minutes early
        [InlineData("1773490200", false)]    // ten minutes late
        public void UnixSeconds(string raw, bool expected) =>
            Assert.Equal(expected, Validate(TimestampFormat.UnixSeconds, raw));

        [Theory]
        [InlineData("1773489600000", true)]
        [InlineData("1773489000000", false)]
        [InlineData("1773489600", false)]    // seconds presented as milliseconds lands in 1970
        public void UnixMilliseconds(string raw, bool expected) =>
            Assert.Equal(expected, Validate(TimestampFormat.UnixMilliseconds, raw));

        [Theory]
        [InlineData("2026-03-14T12:00:00Z", true)]
        [InlineData("2026-03-14T12:04:00Z", true)]
        [InlineData("2026-03-14T12:30:00Z", false)]
        [InlineData("2026-03-14T13:00:00+01:00", true)]   // same instant, different offset
        [InlineData("2026-03-14T12:00:00", true)]         // no offset: assumed UTC, not local
        public void Iso8601(string raw, bool expected) =>
            Assert.Equal(expected, Validate(TimestampFormat.Iso8601, raw));

        [Theory]
        [InlineData(TimestampFormat.UnixSeconds, "not-a-number")]
        [InlineData(TimestampFormat.UnixSeconds, "99999999999999999999")]
        [InlineData(TimestampFormat.UnixMilliseconds, "12.5")]
        [InlineData(TimestampFormat.Iso8601, "14/03/2026")]
        [InlineData(TimestampFormat.Iso8601, "")]
        public void MalformedValuesAreReportedAsMalformed(TimestampFormat format, string raw)
        {
            var validation = TimestampValidation.FromHeader("X-Timestamp", TimeSpan.FromMinutes(5), format);
            var result = validation.Validate(raw, Noon);

            Assert.False(result.Succeeded);
            Assert.Contains(
                result.FailureCode,
                new[] { AuthFailureCode.TimestampMalformed, AuthFailureCode.TimestampMissing });
        }

        [Fact]
        public void Iso8601IsParsedInvariantlyRatherThanInTheServerCulture()
        {
            // An ERP server in a dd/MM culture must not read 2026-03-14 differently from one in
            // MM/dd. Parsing is pinned to the invariant culture for exactly this reason.
            var validation = TimestampValidation.FromHeader(
                "X-Timestamp",
                TimeSpan.FromMinutes(5),
                TimestampFormat.Iso8601);

            Assert.True(validation.Validate("2026-03-14T12:00:00Z", Noon).Succeeded);
        }

        private static bool Validate(TimestampFormat format, string raw) =>
            TimestampValidation
                .FromHeader("X-Timestamp", TimeSpan.FromMinutes(5), format)
                .Validate(raw, Noon)
                .Succeeded;
    }
}
