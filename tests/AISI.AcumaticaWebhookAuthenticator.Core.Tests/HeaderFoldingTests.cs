// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using AISI.AcumaticaWebhookAuthenticator.Diagnostics;
using AISI.AcumaticaWebhookAuthenticator.Signing;
using Xunit;

namespace AISI.AcumaticaWebhookAuthenticator.Tests
{
    /// <summary>
    /// A repeated header reaches the context as distinct values, mirroring the platform's
    /// <c>StringValues</c>. A caller using the single-valued constructor instead delivers it
    /// comma-joined, per HTTP field-value folding, and an intermediary may fold regardless.
    /// Signature extraction has to cope with both shapes: each header value is extracted from
    /// independently, and whole-value extraction additionally splits on commas — which cannot
    /// corrupt a well-formed signature, since neither the hex nor the base64 alphabet contains one.
    /// </summary>
    public class HeaderFoldingTests
    {
        private const string Secret = "It's a Secret to Everybody";
        private const string Body = "Hello, World!";
        private const string Signature =
            "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";
        private const string Decoy =
            "sha256=0000000000000000000000000000000000000000000000000000000000000000";

        [Theory]
        [InlineData(Signature)]
        [InlineData(Signature + "," + Decoy)]
        [InlineData(Decoy + ", " + Signature)]
        [InlineData(Decoy + ",  " + Signature + " ,")]
        public void AFoldedHeaderCarryingTheValidSignatureAuthenticates(string headerValue)
        {
            Assert.True(Authenticate(headerValue).Succeeded);
        }

        [Theory]
        [InlineData(Decoy)]
        [InlineData(Decoy + "," + Decoy)]
        [InlineData("")]
        [InlineData(",,,")]
        public void AFoldedHeaderWithoutAValidSignatureIsRejected(string headerValue)
        {
            Assert.False(Authenticate(headerValue).Succeeded);
        }

        public static IEnumerable<object[]> RepeatedHeadersCarryingTheValidSignature()
        {
            yield return new object[] { new[] { Signature } };
            yield return new object[] { new[] { Signature, Decoy } };
            yield return new object[] { new[] { Decoy, Signature } };
            yield return new object[] { new[] { Decoy, Signature, Decoy } };
        }

        [Theory]
        [MemberData(nameof(RepeatedHeadersCarryingTheValidSignature))]
        public void ARepeatedHeaderIsExtractedFromEachValueIndependently(string[] headerValues)
        {
            // PX.Api.Webhooks.WebhookRequest.Headers is IReadOnlyDictionary<string, StringValues>, so
            // a repeated header reaches the adapter as distinct values. The context carries them
            // through rather than making the adapter flatten and this library re-split.
            var options = WebhookAuthPresets.GitHub(
                new StaticSecretProvider(WebhookSecret.FromUtf8(Secret)));

            WebhookAuthContext request = RequestBuilder.Post()
                .WithBody(Body)
                .WithRepeatedHeader("X-Hub-Signature-256", headerValues)
                .Build();

            Assert.True(new HmacAuthenticator(options).Authenticate(request).Succeeded);
        }

        [Fact]
        public void ARepeatedHeaderWithNoValidValueIsRejected()
        {
            var options = WebhookAuthPresets.GitHub(
                new StaticSecretProvider(WebhookSecret.FromUtf8(Secret)));

            WebhookAuthContext request = RequestBuilder.Post()
                .WithBody(Body)
                .WithRepeatedHeader("X-Hub-Signature-256", Decoy, Decoy)
                .Build();

            Assert.False(new HmacAuthenticator(options).Authenticate(request).Succeeded);
        }

        [Fact]
        public void TryGetHeaderFoldsARepeatedHeaderForTemplateUse()
        {
            // The {header:Name} token needs one string, and HTTP field-value folding is how a
            // repeated header becomes one. Signature extraction deliberately does not go through
            // this path.
            WebhookAuthContext request = RequestBuilder.Post()
                .WithBody(Body)
                .WithRepeatedHeader("X-Trace", "a", "b")
                .Build();

            Assert.True(request.TryGetHeader("X-Trace", out string folded));
            Assert.Equal("a,b", folded);

            Assert.True(request.TryGetHeaderValues("X-Trace", out IReadOnlyList<string> values));
            Assert.Equal(2, values.Count);
            Assert.Equal("a", values[0]);
            Assert.Equal("b", values[1]);
        }

        [Theory]
        [InlineData("sha256=zz,garbage")]
        [InlineData("garbage,sha256=zz")]
        public void TheDiagnosticCodeNamesTheMostSpecificFailureRegardlessOfOrder(string headerValue)
        {
            // 'sha256=zz' carries the right prefix and fails decode; 'garbage' fails the prefix
            // check. The trace must report the candidate that got furthest — malformed — in either
            // order, not whichever failed last.
            AuthResult result = Authenticate(headerValue);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.SignatureMalformed, result.FailureCode);
        }

        [Fact]
        public void SplittingDoesNotCorruptASingleSignature()
        {
            // Neither the hex nor the base64 alphabet contains a comma, so a well-formed signature
            // is never split apart by this. Base64 padding is the interesting case.
            IReadOnlyList<string> extracted = SignatureExtraction.Whole.Extract("D0UMXmhjwBRi4y66TmhJrDlhQABD7zI2fm3p6/QLMo8=");

            Assert.Equal("D0UMXmhjwBRi4y66TmhJrDlhQABD7zI2fm3p6/QLMo8=", Assert.Single(extracted));
        }

        [Fact]
        public void SurroundingWhitespaceIsStripped()
        {
            Assert.Equal("abc", Assert.Single(SignatureExtraction.Whole.Extract("  abc  ")));
        }

        private static AuthResult Authenticate(string headerValue)
        {
            var options = WebhookAuthPresets.GitHub(
                new StaticSecretProvider(WebhookSecret.FromUtf8(Secret)));

            WebhookAuthContext request = RequestBuilder.Post()
                .WithBody(Body)
                .WithHeader("X-Hub-Signature-256", headerValue)
                .Build();

            return new HmacAuthenticator(options).Authenticate(request);
        }
    }

    /// <summary>
    /// When the timestamp lives inside the signature header (Stripe-style) and that header arrives
    /// more than once, each value's signatures were computed over that value's own timestamp.
    /// Verifying every candidate against the first value's timestamp makes a legitimately signed
    /// second value unverifiable.
    /// </summary>
    public class RepeatedSignatureHeaderTimestampTests
    {
        private const string Secret = "whsec_test_secret";
        private const string Body = "{\"id\":\"evt_1\",\"object\":\"event\"}";
        private const string Decoy =
            "0000000000000000000000000000000000000000000000000000000000000000";

        [Fact]
        public void AValidSignatureInTheSecondValueVerifiesAgainstItsOwnTimestamp()
        {
            // First value: stale timestamp, decoy signature. Second value: fresh timestamp, valid
            // signature over that fresh timestamp. Pairing all candidates with the first value's
            // timestamp — the pre-fix behavior — rejects this request as a mismatch.
            const long staleTs = 1614556000;
            const long freshTs = 1614556800;

            AuthResult result = Authenticate(
                receivedAt: freshTs,
                $"t={staleTs},v1={Decoy}",
                $"t={freshTs},v1={Sign(freshTs)}");

            Assert.True(result.Succeeded);
        }

        [Fact]
        public void TheMatchedValuesOwnTimestampIsTheOneValidated()
        {
            // The matching signature belongs to the stale value; the fresh value carries only a
            // decoy. The replay window must be judged against the timestamp that produced the
            // matching payload, not against whichever value happened to carry the freshest one.
            const long now = 1614556800;
            const long staleTs = now - 3600;

            AuthResult result = Authenticate(
                receivedAt: now,
                $"t={now},v1={Decoy}",
                $"t={staleTs},v1={Sign(staleTs)}");

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.TimestampOutsideTolerance, result.FailureCode);
        }

        [Fact]
        public void ASingleValueStillBehavesAsBefore()
        {
            const long ts = 1614556800;

            AuthResult result = Authenticate(receivedAt: ts, $"t={ts},v1={Sign(ts)}");

            Assert.True(result.Succeeded);
        }

        private static AuthResult Authenticate(long receivedAt, params string[] headerValues)
        {
            var options = WebhookAuthPresets.Stripe(
                new StaticSecretProvider(WebhookSecret.FromUtf8(Secret)));

            WebhookAuthContext request = RequestBuilder.Post()
                .WithBody(Body)
                .WithRepeatedHeader("Stripe-Signature", headerValues)
                .ReceivedAtUnixSeconds(receivedAt)
                .Build();

            return new HmacAuthenticator(options).Authenticate(request);
        }

        private static string Sign(long timestamp) =>
            SignatureCodec.Encode(
                HmacComputer.Compute(
                    HmacAlgorithm.Sha256,
                    System.Text.Encoding.UTF8.GetBytes(Secret),
                    System.Text.Encoding.UTF8.GetBytes(timestamp + "." + Body)),
                SignatureEncoding.Hex);
    }
}
