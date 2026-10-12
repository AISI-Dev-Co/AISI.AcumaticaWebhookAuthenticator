// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using AISI.AcumaticaWebhookAuthenticator.Diagnostics;
using AISI.AcumaticaWebhookAuthenticator.Signing;
using Xunit;
using static AISI.AcumaticaWebhookAuthenticator.Tests.Vectors;

namespace AISI.AcumaticaWebhookAuthenticator.Tests
{
    /// <summary>Plausible configurations that could never verify, rejected when the authenticator is constructed.</summary>
    public class MisconfigurationTests
    {
        private static StaticSecretProvider Secret() =>
            new StaticSecretProvider(WebhookSecret.FromUtf8(GitHubSecret));

        public static IEnumerable<object[]> IncoherentConfigurations()
        {
            // A replay window over a timestamp the signature does not cover: a replayer just rewrites it.
            yield return Row(o => o.Timestamp = TimestampValidation.FromHeader("X-Timestamp", TimeSpan.FromMinutes(5)));
            yield return Row(o => o.Template = SignedPayloadTemplate.TimestampDotBody);
            yield return Row(o => o.Algorithm = (HmacAlgorithm)99);
            yield return Row(o => o.Encoding = (SignatureEncoding)42);
            yield return Row(o => o.Template = null!);
            yield return Row(o => o.Extraction = null!);
        }

        [Theory]
        [MemberData(nameof(IncoherentConfigurations))]
        public void AnIncoherentConfigurationIsRejectedAtConstruction(Action<HmacAuthOptions> configure)
        {
            var options = new HmacAuthOptions(Secret(), "X-Signature");
            configure(options);

            Assert.Throws<ArgumentException>(() => new HmacAuthenticator(options));
        }

        [Fact]
        public void ChangingTheOptionsAfterConstructionHasNoEffect()
        {
            HmacAuthOptions options = WebhookAuthPresets.GitHub(Secret());
            var authenticator = new HmacAuthenticator(options);

            options.Timestamp = TimestampValidation.FromHeader("X-Timestamp", TimeSpan.FromMinutes(5));
            options.SignaturePrefix = "totally-different=";
            options.Encoding = SignatureEncoding.Base64;
            options.Algorithm = HmacAlgorithm.Sha512;

            WebhookAuthContext request = RequestBuilder.Post()
                .WithBody(GitHubBody)
                .WithHeader("X-Hub-Signature-256", GitHubSignature)
                .Build();

            Assert.True(authenticator.Authenticate(request).Succeeded);
        }

        [Fact]
        public void TheSignatureTesterReportsAMisconfigurationRatherThanThrowing()
        {
            var options = new HmacAuthOptions(Secret(), "X-Signature")
            {
                Timestamp = TimestampValidation.FromHeader("X-Timestamp", TimeSpan.FromMinutes(5)),
            };

            SignatureTestReport report = WebhookSignatureTester.Test(
                options,
                RequestBuilder.Post().WithBody("x").Build());

            Assert.False(report.Matched);
            Assert.Equal(AuthFailureCode.Misconfigured, report.FailureCode);
            Assert.Contains("{timestamp}", report.Misconfiguration!, StringComparison.Ordinal);
        }

        [Fact]
        public void ACoherentConfigurationReportsNoMisconfiguration()
        {
            SignatureTestReport report = WebhookSignatureTester.Test(
                WebhookAuthPresets.GitHub(Secret()),
                RequestBuilder.Post().WithBody("x").WithHeader("X-Hub-Signature-256", "sha256=00").Build());

            Assert.Null(report.Misconfiguration);
        }

        private static object[] Row(Action<HmacAuthOptions> configure) => new object[] { configure };
    }
}
