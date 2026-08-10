// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using AISI.AcumaticaWebhookAuthenticator.Diagnostics;
using Xunit;

namespace AISI.AcumaticaWebhookAuthenticator.Tests
{
    public class SignatureTesterTests
    {
        private const string Secret = "It's a Secret to Everybody";
        private const string Body = "Hello, World!";
        private const string GoodSignature =
            "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";

        [Fact]
        public void OnAMatch_ItReportsTheMatch()
        {
            SignatureTestReport report = WebhookSignatureTester.Test(
                WebhookAuthPresets.GitHub(new StaticSecretProvider(WebhookSecret.FromUtf8(Secret))),
                Request(GoodSignature));

            Assert.True(report.Matched);
            Assert.Equal(GoodSignature, Assert.Single(report.ExpectedSignatures));
            Assert.Equal(GoodSignature, Assert.Single(report.ProvidedSignatures));
        }

        [Fact]
        public void DuringRotation_ItReportsBothAcceptableSignatures()
        {
            // Reporting only the current secret's digest made a request legitimately signed with the
            // retiring secret display as matched next to an expected value found nowhere on it.
            const string retiringSignature =
                "sha256=e7f4750c1d0580871565739b45147585cd7f2622003135f604ae5d6aac8f9577";

            WebhookSecret secret = WebhookSecret
                .FromUtf8(Secret)
                .WithRotatingUtf8("old-secret", DateTimeOffset.UnixEpoch.AddDays(1));

            SignatureTestReport report = WebhookSignatureTester.Test(
                WebhookAuthPresets.GitHub(new StaticSecretProvider(secret)),
                Request(retiringSignature));

            Assert.True(report.Matched);
            Assert.Equal(2, report.ExpectedSignatures.Count);
            Assert.Contains(retiringSignature, report.ExpectedSignatures);
            Assert.Contains(GoodSignature, report.ExpectedSignatures);
        }

        [Fact]
        public void OnAMismatch_ItShowsBothSidesOfTheDiff()
        {
            // This is the whole point of the tester: "your configuration signed this string and
            // produced that signature; the sender sent this other one" turns an hour of guesswork
            // into a comparison.
            SignatureTestReport report = WebhookSignatureTester.Test(
                WebhookAuthPresets.GitHub(new StaticSecretProvider(WebhookSecret.FromUtf8("wrong-secret"))),
                Request(GoodSignature));

            Assert.False(report.Matched);
            Assert.Equal(AuthFailureCode.SignatureMismatch, report.FailureCode);
            Assert.DoesNotContain(Assert.Single(report.ProvidedSignatures), report.ExpectedSignatures);
            Assert.Equal(Body, report.SignedPayloadPreview);
            Assert.Equal("{body}", report.TemplatePattern);
        }

        [Fact]
        public void ForATimestampedScheme_ItShowsTheCanonicalSignedString()
        {
            const string stripeBody = "{\"id\":\"evt_1\",\"object\":\"event\"}";

            WebhookAuthContext request = RequestBuilder.Post()
                .WithBody(stripeBody)
                .WithHeader("Stripe-Signature", "t=1614556800,v1=deadbeef")
                .ReceivedAtUnixSeconds(1614556800)
                .Build();

            SignatureTestReport report = WebhookSignatureTester.Test(
                WebhookAuthPresets.Stripe(new StaticSecretProvider(WebhookSecret.FromUtf8("whsec_test_secret"))),
                request);

            Assert.False(report.Matched);
            Assert.Equal("1614556800", report.TimestampRaw);
            Assert.Equal("1614556800." + stripeBody, report.SignedPayloadPreview);
        }

        private static WebhookAuthContext Request(string signature) =>
            RequestBuilder.Post()
                .WithBody(Body)
                .WithHeader("X-Hub-Signature-256", signature)
                .Build();
    }
}
