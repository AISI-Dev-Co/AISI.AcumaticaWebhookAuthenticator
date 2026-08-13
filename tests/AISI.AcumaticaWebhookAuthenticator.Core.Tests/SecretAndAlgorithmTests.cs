// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using AISI.AcumaticaWebhookAuthenticator.Diagnostics;
using AISI.AcumaticaWebhookAuthenticator.Signing;
using Xunit;

namespace AISI.AcumaticaWebhookAuthenticator.Tests
{
    public class SecretRotationTests
    {
        private const string CurrentSecret = "It's a Secret to Everybody";
        private const string RetiringSecret = "old-secret";
        private const string Body = "Hello, World!";

        private const string SignedWithCurrent =
            "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";
        private const string SignedWithRetiring =
            "sha256=e7f4750c1d0580871565739b45147585cd7f2622003135f604ae5d6aac8f9577";

        private static readonly DateTimeOffset Now = DateTimeOffset.UnixEpoch.AddDays(100);

        [Fact]
        public void DuringOverlap_TheCurrentSecretIsAccepted()
        {
            Assert.True(Authenticate(SignedWithCurrent, overlapEndsAt: Now.AddDays(1)).Succeeded);
        }

        [Fact]
        public void DuringOverlap_TheRetiringSecretIsAlsoAccepted()
        {
            // A sender mid-rotation emits requests signed with either secret. Without this the
            // integration drops roughly half its traffic for the length of the overlap.
            Assert.True(Authenticate(SignedWithRetiring, overlapEndsAt: Now.AddDays(1)).Succeeded);
        }

        [Fact]
        public void AfterOverlapExpires_TheRetiringSecretStopsWorking()
        {
            // The expiry is what stops a forgotten rotation from leaving a retired secret live
            // indefinitely.
            AuthResult result = Authenticate(SignedWithRetiring, overlapEndsAt: Now.AddSeconds(-1));

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.SignatureMismatch, result.FailureCode);
        }

        [Fact]
        public void AfterOverlapExpires_TheCurrentSecretStillWorks()
        {
            Assert.True(Authenticate(SignedWithCurrent, overlapEndsAt: Now.AddSeconds(-1)).Succeeded);
        }

        [Fact]
        public void WithNoRotationConfigured_OnlyTheCurrentSecretWorks()
        {
            WebhookAuthContext request = Request(SignedWithRetiring);
            var options = WebhookAuthPresets.GitHub(
                new StaticSecretProvider(WebhookSecret.FromUtf8(CurrentSecret)));

            Assert.False(new HmacAuthenticator(options).Authenticate(request).Succeeded);
        }

        private static AuthResult Authenticate(string signature, DateTimeOffset overlapEndsAt)
        {
            WebhookSecret secret = WebhookSecret
                .FromUtf8(CurrentSecret)
                .WithRotatingUtf8(RetiringSecret, overlapEndsAt);

            var options = WebhookAuthPresets.GitHub(new StaticSecretProvider(secret));

            return new HmacAuthenticator(options).Authenticate(Request(signature));
        }

        private static WebhookAuthContext Request(string signature) =>
            RequestBuilder.Post()
                .WithBody(Body)
                .WithHeader("X-Hub-Signature-256", signature)
                .ReceivedAt(Now)
                .Build();
    }

    public class SecretAvailabilityTests
    {
        [Fact]
        public void NoSecretConfigured_DeniesRatherThanAllowing()
        {
            // A misconfigured endpoint must fail closed. Falling through to unauthenticated
            // handling would turn a blank secret field into a publicly writable endpoint.
            WebhookAuthContext request = RequestBuilder.Post()
                .WithBody("Hello, World!")
                .WithHeader("X-Hub-Signature-256", "sha256=00")
                .Build();

            AuthResult result = new HmacAuthenticator(WebhookAuthPresets.GitHub(new NullSecretProvider()))
                .Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.SecretUnavailable, result.FailureCode);
        }

        private sealed class NullSecretProvider : IWebhookSecretProvider
        {
            public WebhookSecret? GetSecret() => null;
        }
    }

    public class AlgorithmTests
    {
        private const string Secret = "It's a Secret to Everybody";
        private const string Body = "Hello, World!";

        [Theory]
        [InlineData(HmacAlgorithm.Sha1, "01dc10d0c83e72ed246219cdd91669667fe2ca59")]
        [InlineData(HmacAlgorithm.Sha256, "757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17")]
        [InlineData(
            HmacAlgorithm.Sha512,
            "11ed355a617e98134e842012a7944ccf59c10256cb182357bd7e3a42013ff07c" +
            "376f8c14cf5cc1923da20b51d64256b2fb8ebbf100aa67a61326f61fea8111bc")]
        public void EachAlgorithmProducesItsKnownDigest(HmacAlgorithm algorithm, string expected)
        {
            byte[] digest = HmacComputer.Compute(
                algorithm,
                System.Text.Encoding.UTF8.GetBytes(Secret),
                System.Text.Encoding.UTF8.GetBytes(Body));

            Assert.Equal(expected, SignatureCodec.Encode(digest, SignatureEncoding.Hex));
        }

        [Fact]
        public void AnAlgorithmMismatchIsRejected()
        {
            // A SHA-1 signature presented to a SHA-256 configuration must not verify.
            WebhookAuthContext request = RequestBuilder.Post()
                .WithBody(Body)
                .WithHeader("X-Hub-Signature-256", "sha256=01dc10d0c83e72ed246219cdd91669667fe2ca59")
                .Build();

            Assert.False(new HmacAuthenticator(
                    WebhookAuthPresets.GitHub(new StaticSecretProvider(WebhookSecret.FromUtf8(Secret))))
                .Authenticate(request).Succeeded);
        }

        [Fact]
        public void SecretsCanBeSuppliedAsHexOrBase64()
        {
            byte[] key = { 0xDE, 0xAD, 0xBE, 0xEF };
            byte[] message = System.Text.Encoding.UTF8.GetBytes(Body);
            byte[] digest = HmacComputer.Compute(HmacAlgorithm.Sha256, key, message);

            Assert.True(WebhookSecret.FromBytes(key)
                .Matches(HmacAlgorithm.Sha256, message, digest, DateTimeOffset.UnixEpoch));
            Assert.True(WebhookSecret.FromHex("deadbeef")
                .Matches(HmacAlgorithm.Sha256, message, digest, DateTimeOffset.UnixEpoch));
            Assert.True(WebhookSecret.FromBase64(Convert.ToBase64String(key))
                .Matches(HmacAlgorithm.Sha256, message, digest, DateTimeOffset.UnixEpoch));
        }

        [Fact]
        public void MutatingTheCallersKeyArrayDoesNotChangeTheSecret()
        {
            // FromBytes used to store the caller's array by reference, so anyone holding it could
            // silently repoint verification at a different key.
            byte[] key = { 0xDE, 0xAD, 0xBE, 0xEF };
            byte[] message = System.Text.Encoding.UTF8.GetBytes(Body);
            byte[] digest = HmacComputer.Compute(HmacAlgorithm.Sha256, key, message);

            WebhookSecret secret = WebhookSecret.FromBytes(key);
            Array.Clear(key, 0, key.Length);

            Assert.True(secret.Matches(HmacAlgorithm.Sha256, message, digest, DateTimeOffset.UnixEpoch));
        }
    }
}
