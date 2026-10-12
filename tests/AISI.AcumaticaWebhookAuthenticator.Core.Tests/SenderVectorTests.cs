// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using AISI.AcumaticaWebhookAuthenticator.Diagnostics;
using Xunit;
using static AISI.AcumaticaWebhookAuthenticator.Tests.Vectors;

namespace AISI.AcumaticaWebhookAuthenticator.Tests
{
    public class SenderVectorTests
    {
        private const string ShopifySecret = "hush";
        private const string ShopifyBody = "{\"id\":820982911946154508,\"email\":\"jon@example.com\"}";
        private const string ShopifySignature = "D0UMXmhjwBRi4y66TmhJrDlhQABD7zI2fm3p6/QLMo8=";

        [Fact]
        public void GitHub_KnownGoodSignature_Authenticates()
        {
            Assert.True(GitHub(GitHubBody, GitHubSignature).Succeeded);
        }

        [Fact]
        public void GitHub_TamperedBody_IsRejected()
        {
            AuthResult result = GitHub(GitHubBody + " ", GitHubSignature);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.SignatureMismatch, result.FailureCode);
        }

        [Fact]
        public void GitHub_MissingPrefix_IsRejected()
        {
            AuthResult result = GitHub(GitHubBody, GitHubSignature.Substring("sha256=".Length));

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.SignaturePrefixMismatch, result.FailureCode);
        }

        [Fact]
        public void GitHub_HeaderAbsent_IsRejected()
        {
            WebhookAuthContext request = RequestBuilder.Post().WithBody(GitHubBody).Build();

            AuthResult result = new HmacAuthenticator(WebhookAuthPresets.GitHub(Secret(GitHubSecret)))
                .Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.SignatureHeaderMissing, result.FailureCode);
        }

        [Fact]
        public void Shopify_KnownGoodSignature_Authenticates()
        {
            Assert.True(Shopify(ShopifySecret, ShopifySignature).Succeeded);
        }

        [Fact]
        public void Shopify_SignatureFromADifferentSecret_IsRejected()
        {
            AuthResult result = Shopify("wrong", ShopifySignature);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.SignatureMismatch, result.FailureCode);
        }

        [Fact]
        public void Shopify_MalformedBase64_IsRejectedNotThrown()
        {
            AuthResult result = Shopify(ShopifySecret, "not valid base64 !!");

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.SignatureMalformed, result.FailureCode);
        }

        [Fact]
        public void Stripe_KnownGoodCompoundHeader_Authenticates()
        {
            Assert.True(Stripe($"t={StripeTimestamp},v1={StripeV1}").Succeeded);
        }

        [Fact]
        public void Stripe_SignsTheTimestampAsWellAsTheBody()
        {
            AuthResult result = Stripe($"t={StripeTimestamp + 1},v1={StripeV1}");

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.SignatureMismatch, result.FailureCode);
        }

        [Fact]
        public void Stripe_TriesEveryV1Element()
        {
            Assert.True(Stripe($"t={StripeTimestamp},v1={StripeDecoy},v1={StripeV1}").Succeeded);
        }

        [Fact]
        public void Stripe_V0ElementIsIgnored()
        {
            AuthResult result = Stripe($"t={StripeTimestamp},v0={StripeV1}");

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.SignatureElementMissing, result.FailureCode);
        }

        [Theory]
        [InlineData(0, true)]
        [InlineData(299, true)]
        [InlineData(-299, true)]
        [InlineData(360, false)]
        [InlineData(-360, false)]
        public void Stripe_IsAcceptedOnlyInsideTheToleranceWindow(int driftSeconds, bool expected)
        {
            AuthResult result = Stripe($"t={StripeTimestamp},v1={StripeV1}", StripeTimestamp + driftSeconds);

            Assert.Equal(expected, result.Succeeded);
            if (!expected)
            {
                Assert.Equal(AuthFailureCode.TimestampOutsideTolerance, result.FailureCode);
            }
        }

        [Fact]
        public void Stripe_NonNumericTimestamp_IsRejected()
        {
            // Correctly signed, so this also pins that the signature is checked before the timestamp.
            AuthResult result = Stripe($"t=not-a-timestamp,v1={SignStripe("not-a-timestamp")}");

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.TimestampMalformed, result.FailureCode);
        }

        private static StaticSecretProvider Secret(string value) =>
            new StaticSecretProvider(WebhookSecret.FromUtf8(value));

        private static AuthResult GitHub(string body, string signature)
        {
            WebhookAuthContext request = RequestBuilder.Post()
                .WithBody(body)
                .WithHeader("X-Hub-Signature-256", signature)
                .Build();

            return new HmacAuthenticator(WebhookAuthPresets.GitHub(Secret(GitHubSecret))).Authenticate(request);
        }

        private static AuthResult Shopify(string secret, string signature)
        {
            WebhookAuthContext request = RequestBuilder.Post()
                .WithBody(ShopifyBody)
                .WithHeader("X-Shopify-Hmac-Sha256", signature)
                .Build();

            return new HmacAuthenticator(WebhookAuthPresets.Shopify(Secret(secret))).Authenticate(request);
        }

        private static AuthResult Stripe(string signatureHeader, long receivedAt = StripeTimestamp)
        {
            WebhookAuthContext request = RequestBuilder.Post()
                .WithBody(StripeBody)
                .WithHeader("Stripe-Signature", signatureHeader)
                .ReceivedAtUnixSeconds(receivedAt)
                .Build();

            return new HmacAuthenticator(WebhookAuthPresets.Stripe(Secret(StripeSecret))).Authenticate(request);
        }
    }
}
