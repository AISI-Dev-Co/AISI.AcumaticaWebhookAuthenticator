// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using AISI.AcumaticaWebhookAuthenticator.Diagnostics;
using Xunit;

namespace AISI.AcumaticaWebhookAuthenticator.Tests
{
    public class SenderVectorTests
    {
        // Published in GitHub's own webhook documentation, which makes this an external anchor
        // rather than a value this library computed for itself.
        private const string GitHubSecret = "It's a Secret to Everybody";
        private const string GitHubBody = "Hello, World!";
        private const string GitHubSignature =
            "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";

        private const string ShopifySecret = "hush";
        private const string ShopifyBody = "{\"id\":820982911946154508,\"email\":\"jon@example.com\"}";
        private const string ShopifySignature = "D0UMXmhjwBRi4y66TmhJrDlhQABD7zI2fm3p6/QLMo8=";

        private const string StripeSecret = "whsec_test_secret";
        private const string StripeBody = "{\"id\":\"evt_1\",\"object\":\"event\"}";
        private const long StripeTimestamp = 1614556800;
        private const string StripeV1 =
            "7a0685c65fcda9f1dd585b6eaa74ead6d954e5895ecc08263afbd424c5661b46";

        private static StaticSecretProvider Secret(string value) =>
            new StaticSecretProvider(WebhookSecret.FromUtf8(value));

        [Fact]
        public void GitHub_KnownGoodSignature_Authenticates()
        {
            WebhookAuthContext request = RequestBuilder.Post()
                .WithBody(GitHubBody)
                .WithHeader("X-Hub-Signature-256", GitHubSignature)
                .Build();

            AuthResult result = new HmacAuthenticator(WebhookAuthPresets.GitHub(Secret(GitHubSecret)))
                .Authenticate(request);

            Assert.True(result.Succeeded);
        }

        [Fact]
        public void GitHub_TamperedBody_IsRejected()
        {
            WebhookAuthContext request = RequestBuilder.Post()
                .WithBody(GitHubBody + " ")
                .WithHeader("X-Hub-Signature-256", GitHubSignature)
                .Build();

            AuthResult result = new HmacAuthenticator(WebhookAuthPresets.GitHub(Secret(GitHubSecret)))
                .Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.SignatureMismatch, result.FailureCode);
        }

        [Fact]
        public void GitHub_MissingPrefix_IsRejected()
        {
            WebhookAuthContext request = RequestBuilder.Post()
                .WithBody(GitHubBody)
                .WithHeader("X-Hub-Signature-256", GitHubSignature.Substring("sha256=".Length))
                .Build();

            AuthResult result = new HmacAuthenticator(WebhookAuthPresets.GitHub(Secret(GitHubSecret)))
                .Authenticate(request);

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
        public void GitHub_HeaderNameIsMatchedCaseInsensitively()
        {
            WebhookAuthContext request = RequestBuilder.Post()
                .WithBody(GitHubBody)
                .WithHeader("x-hub-signature-256", GitHubSignature)
                .Build();

            Assert.True(new HmacAuthenticator(WebhookAuthPresets.GitHub(Secret(GitHubSecret)))
                .Authenticate(request).Succeeded);
        }

        [Fact]
        public void Shopify_KnownGoodSignature_Authenticates()
        {
            WebhookAuthContext request = RequestBuilder.Post()
                .WithBody(ShopifyBody)
                .WithHeader("X-Shopify-Hmac-Sha256", ShopifySignature)
                .Build();

            Assert.True(new HmacAuthenticator(WebhookAuthPresets.Shopify(Secret(ShopifySecret)))
                .Authenticate(request).Succeeded);
        }

        [Fact]
        public void Shopify_SignatureFromADifferentSecret_IsRejected()
        {
            WebhookAuthContext request = RequestBuilder.Post()
                .WithBody(ShopifyBody)
                .WithHeader("X-Shopify-Hmac-Sha256", ShopifySignature)
                .Build();

            AuthResult result = new HmacAuthenticator(WebhookAuthPresets.Shopify(Secret("wrong")))
                .Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.SignatureMismatch, result.FailureCode);
        }

        [Fact]
        public void Shopify_MalformedBase64_IsRejectedNotThrown()
        {
            WebhookAuthContext request = RequestBuilder.Post()
                .WithBody(ShopifyBody)
                .WithHeader("X-Shopify-Hmac-Sha256", "not valid base64 !!")
                .Build();

            AuthResult result = new HmacAuthenticator(WebhookAuthPresets.Shopify(Secret(ShopifySecret)))
                .Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.SignatureMalformed, result.FailureCode);
        }

        [Fact]
        public void Stripe_KnownGoodCompoundHeader_Authenticates()
        {
            WebhookAuthContext request = StripeRequest($"t={StripeTimestamp},v1={StripeV1}");

            Assert.True(new HmacAuthenticator(WebhookAuthPresets.Stripe(Secret(StripeSecret)))
                .Authenticate(request).Succeeded);
        }

        [Fact]
        public void Stripe_SignsTheTimestampAsWellAsTheBody()
        {
            // Same body and secret, different timestamp: if the timestamp were not part of the
            // signed payload this would still verify.
            WebhookAuthContext request = StripeRequest($"t={StripeTimestamp + 1},v1={StripeV1}");

            AuthResult result = new HmacAuthenticator(WebhookAuthPresets.Stripe(Secret(StripeSecret)))
                .Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.SignatureMismatch, result.FailureCode);
        }

        [Fact]
        public void Stripe_TriesEveryV1Element()
        {
            // Stripe emits one v1 per active endpoint secret, so the matching signature is not
            // necessarily the first one in the header.
            WebhookAuthContext request = StripeRequest(
                $"t={StripeTimestamp},v1=0000000000000000000000000000000000000000000000000000000000000000,v1={StripeV1}");

            Assert.True(new HmacAuthenticator(WebhookAuthPresets.Stripe(Secret(StripeSecret)))
                .Authenticate(request).Succeeded);
        }

        [Fact]
        public void Stripe_V0ElementIsIgnored()
        {
            WebhookAuthContext request = StripeRequest($"t={StripeTimestamp},v0={StripeV1}");

            AuthResult result = new HmacAuthenticator(WebhookAuthPresets.Stripe(Secret(StripeSecret)))
                .Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.SignatureElementMissing, result.FailureCode);
        }

        [Fact]
        public void Stripe_ReplayOutsideTheToleranceWindow_IsRejected()
        {
            // A correctly signed request, captured and replayed six minutes later.
            WebhookAuthContext request = RequestBuilder.Post()
                .WithBody(StripeBody)
                .WithHeader("Stripe-Signature", $"t={StripeTimestamp},v1={StripeV1}")
                .ReceivedAtUnixSeconds(StripeTimestamp + 360)
                .Build();

            AuthResult result = new HmacAuthenticator(WebhookAuthPresets.Stripe(Secret(StripeSecret)))
                .Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.TimestampOutsideTolerance, result.FailureCode);
        }

        [Fact]
        public void Stripe_RequestFromTheFuture_IsRejected()
        {
            WebhookAuthContext request = RequestBuilder.Post()
                .WithBody(StripeBody)
                .WithHeader("Stripe-Signature", $"t={StripeTimestamp},v1={StripeV1}")
                .ReceivedAtUnixSeconds(StripeTimestamp - 360)
                .Build();

            AuthResult result = new HmacAuthenticator(WebhookAuthPresets.Stripe(Secret(StripeSecret)))
                .Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.TimestampOutsideTolerance, result.FailureCode);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(299)]
        [InlineData(-299)]
        public void Stripe_InsideTheToleranceWindow_Authenticates(int driftSeconds)
        {
            WebhookAuthContext request = RequestBuilder.Post()
                .WithBody(StripeBody)
                .WithHeader("Stripe-Signature", $"t={StripeTimestamp},v1={StripeV1}")
                .ReceivedAtUnixSeconds(StripeTimestamp + driftSeconds)
                .Build();

            Assert.True(new HmacAuthenticator(WebhookAuthPresets.Stripe(Secret(StripeSecret)))
                .Authenticate(request).Succeeded);
        }

        [Fact]
        public void Stripe_NonNumericTimestamp_IsRejected()
        {
            // The signature has to match before the timestamp is even looked at, so this asserts
            // the ordering as much as the parsing: a malformed timestamp on an otherwise valid
            // request is reported as malformed rather than as a mismatch.
            const string body = "{\"id\":\"evt_1\",\"object\":\"event\"}";
            string signature = ComputeStripeSignature("not-a-timestamp", body, StripeSecret);

            WebhookAuthContext request = RequestBuilder.Post()
                .WithBody(body)
                .WithHeader("Stripe-Signature", $"t=not-a-timestamp,v1={signature}")
                .ReceivedAtUnixSeconds(StripeTimestamp)
                .Build();

            AuthResult result = new HmacAuthenticator(WebhookAuthPresets.Stripe(Secret(StripeSecret)))
                .Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.TimestampMalformed, result.FailureCode);
        }

        private static WebhookAuthContext StripeRequest(string signatureHeader) =>
            RequestBuilder.Post()
                .WithBody(StripeBody)
                .WithHeader("Stripe-Signature", signatureHeader)
                .ReceivedAtUnixSeconds(StripeTimestamp)
                .Build();

        private static string ComputeStripeSignature(string timestamp, string body, string secret)
        {
            byte[] signed = System.Text.Encoding.UTF8.GetBytes(timestamp + "." + body);
            byte[] key = System.Text.Encoding.UTF8.GetBytes(secret);

            return Signing.SignatureCodec.Encode(
                Signing.HmacComputer.Compute(Signing.HmacAlgorithm.Sha256, key, signed),
                Signing.SignatureEncoding.Hex);
        }

        [Fact]
        public void JwtBearer_KnownGoodToken_Authenticates()
        {
            const string secret = "It's a Secret to Everybody";
            var received = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);
            string jwt = JwtAuthenticator.Compact(
                Signing.HmacAlgorithm.Sha256,
                System.Text.Encoding.UTF8.GetBytes(secret),
                "{\"exp\":1700003600,\"iss\":\"hooks\",\"aud\":\"" + RequestBuilder.DefaultWebhookId.ToString("D") + "\",\"bh\":\"" + JwtAuthenticator.Base64UrlEncode(JwtAuthenticator.ComputeBodyHash(System.Array.Empty<byte>())) + "\"}");

            WebhookAuthContext request = RequestBuilder.Post()
                .ReceivedAt(received)
                .WithHeader("Authorization", "Bearer " + jwt)
                .Build();

            Assert.True(new JwtAuthenticator(WebhookAuthPresets.JwtBearer(Secret(secret)))
                .Authenticate(request).Succeeded);
        }

        [Fact]
        public void JwtBearer_TamperedPayload_IsRejected()
        {
            const string secret = "It's a Secret to Everybody";
            var received = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);
            string jwt = JwtAuthenticator.Compact(
                Signing.HmacAlgorithm.Sha256,
                System.Text.Encoding.UTF8.GetBytes(secret),
                "{\"exp\":1700003600,\"aud\":\"" + RequestBuilder.DefaultWebhookId.ToString("D") + "\",\"bh\":\"" + JwtAuthenticator.Base64UrlEncode(JwtAuthenticator.ComputeBodyHash(System.Array.Empty<byte>())) + "\"}");
            string[] parts = jwt.Split('.');
            string tampered = parts[0] + "." +
                JwtAuthenticator.Base64UrlEncode(System.Text.Encoding.UTF8.GetBytes("{\"exp\":9999999999}")) +
                "." + parts[2];

            WebhookAuthContext request = RequestBuilder.Post()
                .ReceivedAt(received)
                .WithHeader("Authorization", "Bearer " + tampered)
                .Build();

            AuthResult result = new JwtAuthenticator(WebhookAuthPresets.JwtBearer(Secret(secret)))
                .Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.SignatureMismatch, result.FailureCode);
        }
    }
}
