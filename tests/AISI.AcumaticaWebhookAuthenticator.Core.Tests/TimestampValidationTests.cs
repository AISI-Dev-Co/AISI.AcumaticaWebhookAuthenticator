// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Globalization;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using AISI.AcumaticaWebhookAuthenticator.Diagnostics;
using AISI.AcumaticaWebhookAuthenticator.Signing;
using Xunit;
using static AISI.AcumaticaWebhookAuthenticator.Tests.Vectors;

namespace AISI.AcumaticaWebhookAuthenticator.Tests
{
    public class TimestampValidationTests
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
        [InlineData(TimestampFormat.UnixSeconds, "not-a-number", AuthFailureCode.TimestampMalformed)]
        [InlineData(TimestampFormat.UnixSeconds, "99999999999999999999", AuthFailureCode.TimestampMalformed)]
        [InlineData(TimestampFormat.UnixSeconds, "99999999999999", AuthFailureCode.TimestampMalformed)]
        [InlineData(TimestampFormat.UnixMilliseconds, "12.5", AuthFailureCode.TimestampMalformed)]
        [InlineData(TimestampFormat.UnixMilliseconds, "99999999999999999", AuthFailureCode.TimestampMalformed)]
        [InlineData(TimestampFormat.Iso8601, "14/03/2026", AuthFailureCode.TimestampMalformed)]
        [InlineData(TimestampFormat.Iso8601, "", AuthFailureCode.TimestampMissing)]
        [InlineData(TimestampFormat.UnixSeconds, " ", AuthFailureCode.TimestampMissing)]
        public void InvalidValuesAreRejectedWithTheirCode(TimestampFormat format, string raw, string expectedCode)
        {
            AuthResult result = TimestampValidation
                .FromHeader("X-Timestamp", TimeSpan.FromMinutes(5), format)
                .Validate(raw, Noon);

            Assert.False(result.Succeeded);
            Assert.Equal(expectedCode, result.FailureCode);
        }

        [Fact]
        public void Iso8601IsParsedInvariantlyRatherThanInTheServerCulture()
        {
            // th-TH uses the Buddhist calendar: parsed in that culture, this RFC 3339 form lands in 1483.
            CultureInfo original = CultureInfo.CurrentCulture;

            try
            {
                CultureInfo.CurrentCulture = new CultureInfo("th-TH");

                Assert.True(Validate(TimestampFormat.Iso8601, "2026-03-14 12:00:00Z"));
            }
            finally
            {
                CultureInfo.CurrentCulture = original;
            }
        }

        [Fact]
        public void AnUndefinedFormatIsRejected()
        {
            Assert.Throws<ArgumentOutOfRangeException>(
                () => TimestampValidation.FromHeader("X-Timestamp", TimeSpan.FromMinutes(5), (TimestampFormat)99));

            Assert.Throws<ArgumentOutOfRangeException>(
                () => TimestampValidation.FromSignatureHeaderElement("t", TimeSpan.FromMinutes(5), (TimestampFormat)99));
        }

        [Fact]
        public void ANegativeToleranceIsRejected()
        {
            Assert.Throws<ArgumentOutOfRangeException>(
                () => TimestampValidation.FromHeader("X-Timestamp", TimeSpan.FromMinutes(-5)));

            Assert.Throws<ArgumentOutOfRangeException>(
                () => TimestampValidation.FromSignatureHeaderElement("t", TimeSpan.FromSeconds(-1)));
        }

        [Fact]
        public void AZeroToleranceIsAllowed()
        {
            TimestampValidation validation = TimestampValidation.FromHeader("X-Timestamp", TimeSpan.Zero);

            Assert.True(validation.Validate("0", DateTimeOffset.UnixEpoch).Succeeded);
            Assert.False(validation.Validate("1", DateTimeOffset.UnixEpoch).Succeeded);
        }

        [Fact]
        public void CustomSeparatorsReachTheTimestampReader()
        {
            var options = new HmacAuthOptions(new StaticSecretProvider(WebhookSecret.FromUtf8(StripeSecret)), "X-Signature")
            {
                Extraction = SignatureExtraction.KeyValueElement("sig", pairSeparator: ';', keyValueSeparator: ':'),
                Template = SignedPayloadTemplate.TimestampDotBody,
                Timestamp = TimestampValidation.FromSignatureHeaderElement(
                    "ts",
                    TimeSpan.FromMinutes(5),
                    TimestampFormat.UnixSeconds,
                    pairSeparator: ';',
                    keyValueSeparator: ':'),
            };

            WebhookAuthContext request = RequestBuilder.Post()
                .WithBody(StripeBody)
                .WithHeader("X-Signature", $"ts:{StripeTimestamp};sig:{SignStripe(StripeTimestamp)}")
                .ReceivedAtUnixSeconds(StripeTimestamp)
                .Build();

            Assert.True(new HmacAuthenticator(options).Authenticate(request).Succeeded);
        }

        private static bool Validate(TimestampFormat format, string raw) =>
            TimestampValidation
                .FromHeader("X-Timestamp", TimeSpan.FromMinutes(5), format)
                .Validate(raw, Noon)
                .Succeeded;
    }
}
