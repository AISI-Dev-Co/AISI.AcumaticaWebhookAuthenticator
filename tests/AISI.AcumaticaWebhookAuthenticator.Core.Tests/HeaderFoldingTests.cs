// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using Xunit;

namespace AISI.AcumaticaWebhookAuthenticator.Tests
{
    /// <summary>
    /// <see cref="WebhookAuthContext"/> asks callers to fold a repeated header into one
    /// comma-separated value, which is what HTTP field-value semantics specify and what an adapter
    /// flattening an ASP.NET <c>StringValues</c> will naturally produce. Whole-value extraction then
    /// has to cope with the result, which it previously did not: the folded string went straight to
    /// a hex decoder and every such request failed as malformed.
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
}
