// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using AISI.AcumaticaWebhookAuthenticator.Diagnostics;
using AISI.AcumaticaWebhookAuthenticator.Signing;
using Xunit;

namespace AISI.AcumaticaWebhookAuthenticator.Tests
{
    /// <summary>
    /// Configurations that look plausible, compile, and would be wrong at runtime. Each of these is
    /// rejected when the authenticator is constructed, so the failure lands on the developer who
    /// wrote it rather than on whoever is reading a 401 six months later.
    /// </summary>
    public class MisconfigurationTests
    {
        private static IWebhookSecretProvider Secret() =>
            new StaticSecretProvider(WebhookSecret.FromUtf8("secret"));

        [Fact]
        public void AReplayWindowOverAnUnsignedTimestampIsRejected()
        {
            // The dangerous one. Validating a timestamp the signature does not cover is worth
            // nothing: a replayer rewrites it and the request verifies exactly as before.
            var options = new HmacAuthOptions(Secret(), "X-Signature")
            {
                Template = SignedPayloadTemplate.Body,
                Timestamp = TimestampValidation.FromHeader("X-Timestamp", TimeSpan.FromMinutes(5)),
            };

            ArgumentException error = Assert.Throws<ArgumentException>(() => new HmacAuthenticator(options));
            Assert.Contains("{timestamp}", error.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void ATimestampTokenWithNoTimestampSourceIsRejected()
        {
            // The merely useless one: every request would fail with timestamp_missing, which reads
            // as a sender problem rather than the configuration error it is.
            var options = new HmacAuthOptions(Secret(), "X-Signature")
            {
                Template = SignedPayloadTemplate.TimestampDotBody,
                Timestamp = null,
            };

            Assert.Throws<ArgumentException>(() => new HmacAuthenticator(options));
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
            // Degenerate but coherent: the timestamp must equal the receipt second exactly.
            TimestampValidation validation = TimestampValidation.FromHeader("X-Timestamp", TimeSpan.Zero);

            Assert.True(validation.Validate("0", DateTimeOffset.UnixEpoch).Succeeded);
            Assert.False(validation.Validate("1", DateTimeOffset.UnixEpoch).Succeeded);
        }

        [Fact]
        public void CustomSeparatorsReachTheTimestampReader()
        {
            // Regression: an earlier revision took the separators as a parameter and then rebuilt the
            // extraction with the defaults, so a sender using anything but ',' and '=' silently lost
            // its timestamp and every request failed as a signature mismatch.
            var options = new HmacAuthOptions(Secret(), "X-Signature")
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

            const string body = "{\"ok\":true}";
            string signature = Sign("1614556800." + body, "secret");

            WebhookAuthContext request = RequestBuilder.Post()
                .WithBody(body)
                .WithHeader("X-Signature", $"ts:1614556800;sig:{signature}")
                .ReceivedAtUnixSeconds(1614556800)
                .Build();

            Assert.True(new HmacAuthenticator(options).Authenticate(request).Succeeded);
        }

        [Fact]
        public void MutatingTheOptionsAfterConstructionCannotDefeatTheCoherenceCheck()
        {
            // HmacAuthOptions is a mutable initializer bag. Reading it per request would let this
            // assignment walk straight past the constructor's check and reinstate the replay window
            // over a timestamp nothing signs.
            var options = WebhookAuthPresets.GitHub(Secret());
            var authenticator = new HmacAuthenticator(options);

            options.Timestamp = TimestampValidation.FromHeader("X-Timestamp", TimeSpan.FromMinutes(5));
            options.SignaturePrefix = "totally-different=";

            Assert.Equal("HMAC", authenticator.Code);

            WebhookAuthContext request = RequestBuilder.Post()
                .WithBody("Hello, World!")
                .WithHeader("X-Hub-Signature-256", "sha256=" + Sign("Hello, World!", "secret"))
                .Build();

            Assert.True(authenticator.Authenticate(request).Succeeded);
        }

        [Fact]
        public void TheSignatureTesterReportsAMisconfigurationRatherThanThrowing()
        {
            var options = new HmacAuthOptions(Secret(), "X-Signature")
            {
                Template = SignedPayloadTemplate.Body,
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

        [Fact]
        public void AnUndefinedAlgorithmIsRejectedAtConstruction()
        {
            // Without this the cast lands at request time, where HmacComputer throws and the caller
            // gets a 500 that reads as a library fault rather than a configuration one.
            var options = new HmacAuthOptions(Secret(), "X-Signature")
            {
                Algorithm = (HmacAlgorithm)99,
            };

            Assert.Throws<ArgumentException>(() => new HmacAuthenticator(options));
        }

        [Fact]
        public void AnUndefinedEncodingIsRejectedAtConstruction()
        {
            // This one is worse than a crash: every decode silently fails, so every request 401s as
            // signature_malformed and the endpoint looks like the sender's fault indefinitely.
            var options = new HmacAuthOptions(Secret(), "X-Signature")
            {
                Encoding = (SignatureEncoding)42,
            };

            Assert.Throws<ArgumentException>(() => new HmacAuthenticator(options));
        }

        [Fact]
        public void ADefaultAuthResultReportsAFailureRatherThanANullCode()
        {
            AuthResult result = default;

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.Unspecified, result.FailureCode);
        }

        [Fact]
        public void AnAbsentHeaderYieldsEmptyRatherThanNull()
        {
            WebhookAuthContext request = RequestBuilder.Post().WithBody("x").Build();

            Assert.False(request.TryGetHeader("X-Absent", out string value));
            Assert.Equal(string.Empty, value);
        }

        private static string Sign(string message, string secret) =>
            SignatureCodec.Encode(
                HmacComputer.Compute(
                    HmacAlgorithm.Sha256,
                    System.Text.Encoding.UTF8.GetBytes(secret),
                    System.Text.Encoding.UTF8.GetBytes(message)),
                SignatureEncoding.Hex);
    }

    /// <summary>
    /// The preview string is a diagnostic. It must not be built on the verification path, where it
    /// would allocate a full extra copy of every payload for something nobody reads.
    /// </summary>
    public class PreviewCaptureTests
    {
        [Fact]
        public void ResolveDoesNotBuildThePreviewByDefault()
        {
            WebhookAuthContext request = RequestBuilder.Post().WithBody("a fairly large payload").Build();

            TemplateResolution resolution = SignedPayloadTemplate.Body.Resolve(request, null);

            Assert.True(resolution.Success);
            Assert.Equal(string.Empty, resolution.Preview);
        }

        [Fact]
        public void ResolveBuildsThePreviewWhenAsked()
        {
            WebhookAuthContext request = RequestBuilder.Post().WithBody("payload").Build();

            TemplateResolution resolution = SignedPayloadTemplate.Body.Resolve(request, null, capturePreview: true);

            Assert.Equal("payload", resolution.Preview);
        }

        [Fact]
        public void TheDigestIsUnaffectedByWhetherThePreviewWasCaptured()
        {
            byte[] body = { 0x7B, 0xFF, 0xFE, 0x7D };
            WebhookAuthContext request = RequestBuilder.Post().WithBodyBytes(body).Build();

            Assert.Equal(
                SignedPayloadTemplate.Body.Resolve(request, null).Bytes,
                SignedPayloadTemplate.Body.Resolve(request, null, capturePreview: true).Bytes);
        }
    }
}
