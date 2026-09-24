// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Globalization;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using AISI.AcumaticaWebhookAuthenticator.Diagnostics;
using Xunit;
using static AISI.AcumaticaWebhookAuthenticator.Tests.Vectors;

namespace AISI.AcumaticaWebhookAuthenticator.Tests
{
    public class SignatureTesterTests
    {
        [Fact]
        public void OnAMatch_ItReportsTheMatch()
        {
            SignatureTestReport report = WebhookSignatureTester.Test(
                WebhookAuthPresets.GitHub(Provider(WebhookSecret.FromUtf8(GitHubSecret))),
                GitHubRequest(GitHubSignature));

            Assert.True(report.Matched);
            Assert.Equal(new[] { GitHubSignature }, report.ExpectedSignatures);
            Assert.Equal(new[] { GitHubSignature }, report.ProvidedSignatures);
        }

        [Fact]
        public void DuringRotation_ItReportsBothAcceptableSignatures()
        {
            WebhookSecret secret = WebhookSecret
                .FromUtf8(GitHubSecret)
                .WithRotatingUtf8(GitHubRetiringSecret, DateTimeOffset.UnixEpoch.AddDays(1));

            SignatureTestReport report = WebhookSignatureTester.Test(
                WebhookAuthPresets.GitHub(Provider(secret)),
                GitHubRequest(GitHubRetiringSignature));

            Assert.True(report.Matched);
            Assert.Equal(new[] { GitHubSignature, GitHubRetiringSignature }, report.ExpectedSignatures);
        }

        [Fact]
        public void OnAMismatch_ItShowsBothSidesOfTheDiff()
        {
            SignatureTestReport report = WebhookSignatureTester.Test(
                WebhookAuthPresets.GitHub(Provider(WebhookSecret.FromUtf8("wrong-secret"))),
                GitHubRequest(GitHubSignature));

            Assert.False(report.Matched);
            Assert.Equal(AuthFailureCode.SignatureMismatch, report.FailureCode);
            Assert.DoesNotContain(Assert.Single(report.ProvidedSignatures), report.ExpectedSignatures);
            Assert.Equal(GitHubBody, report.SignedPayloadPreview);
            Assert.Equal("{body}", report.TemplatePattern);
        }

        [Fact]
        public void ForATimestampedScheme_ItShowsTheCanonicalSignedString()
        {
            SignatureTestReport report = TestStripe($"t={StripeTimestamp},v1=deadbeef");

            Assert.False(report.Matched);
            Assert.Equal(Timestamp(StripeTimestamp), report.TimestampRaw);
            Assert.Equal(Timestamp(StripeTimestamp) + "." + StripeBody, report.SignedPayloadPreview);
        }

        [Fact]
        public void AHeaderValueWithoutASignatureDoesNotSupplyTheTimestamp()
        {
            SignatureTestReport report = TestStripe(
                $"t={StripeTimestamp - 3600}",
                $"t={StripeTimestamp},v1={StripeV1}");

            Assert.True(report.Matched);
            Assert.Equal(Timestamp(StripeTimestamp), report.TimestampRaw);
            Assert.Equal(Timestamp(StripeTimestamp) + "." + StripeBody, report.SignedPayloadPreview);
            Assert.Equal(new[] { StripeV1 }, report.ExpectedSignatures);
        }

        private static StaticSecretProvider Provider(WebhookSecret secret) => new StaticSecretProvider(secret);

        private static string Timestamp(long seconds) => seconds.ToString(CultureInfo.InvariantCulture);

        private static WebhookAuthContext GitHubRequest(string signature) =>
            RequestBuilder.Post()
                .WithBody(GitHubBody)
                .WithHeader("X-Hub-Signature-256", signature)
                .Build();

        private static SignatureTestReport TestStripe(params string[] headerValues)
        {
            WebhookAuthContext request = RequestBuilder.Post()
                .WithBody(StripeBody)
                .WithRepeatedHeader("Stripe-Signature", headerValues)
                .ReceivedAtUnixSeconds(StripeTimestamp)
                .Build();

            return WebhookSignatureTester.Test(
                WebhookAuthPresets.Stripe(Provider(WebhookSecret.FromUtf8(StripeSecret))),
                request);
        }
    }
}
