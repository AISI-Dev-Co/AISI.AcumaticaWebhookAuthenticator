// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using AISI.AcumaticaWebhookAuthenticator.Diagnostics;
using Xunit;

namespace AISI.AcumaticaWebhookAuthenticator.Tests
{
    public class SharedSecretAuthenticatorTests
    {
        private static SharedSecretAuthenticator Authenticator(string secret, string? prefix = null) =>
            new(new StaticSecretProvider(WebhookSecret.FromUtf8(secret)), "X-Api-Key", prefix);

        private static WebhookAuthContext Request(string apiKey) =>
            RequestBuilder.Post().WithHeader("X-Api-Key", apiKey).Build();

        [Fact]
        public void MatchingSecret_Authenticates()
        {
            Assert.True(Authenticator("s3cret").Authenticate(Request("s3cret")).Succeeded);
        }

        [Theory]
        [InlineData("wrong")]
        [InlineData("s3cret-and-more")]
        public void WrongSecret_FailsAsMismatch(string apiKey)
        {
            AuthResult result = Authenticator("s3cret").Authenticate(Request(apiKey));

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.CredentialMismatch, result.FailureCode);
        }

        [Fact]
        public void MissingHeader_FailsAsCredentialMissing()
        {
            AuthResult result = Authenticator("s3cret").Authenticate(RequestBuilder.Post().Build());

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.CredentialMissing, result.FailureCode);
        }

        [Fact]
        public void NullSecret_FailsClosedRatherThanFallingBackToUnauthenticated()
        {
            var authenticator = new SharedSecretAuthenticator(new NullSecretProvider(), "X-Api-Key");

            AuthResult result = authenticator.Authenticate(Request("anything"));

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.SecretUnavailable, result.FailureCode);
        }

        [Fact]
        public void Prefix_IsStrippedBeforeComparison()
        {
            Assert.True(Authenticator("s3cret", "Token ").Authenticate(Request("Token s3cret")).Succeeded);
        }

        [Fact]
        public void MissingPrefix_FailsAsMalformed()
        {
            AuthResult result = Authenticator("s3cret", "Token ").Authenticate(Request("s3cret"));

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.CredentialMalformed, result.FailureCode);
        }

        [Theory]
        [InlineData(-1, true)]
        [InlineData(0, true)]
        [InlineData(1, false)]
        public void RotatingSecret_IsAcceptedUntilItsExpiry(int hoursFromExpiry, bool accepted)
        {
            var expiry = DateTimeOffset.UnixEpoch.AddDays(1);
            var provider = new StaticSecretProvider(
                WebhookSecret.FromUtf8("new").WithRotatingUtf8("old", expiry));

            WebhookAuthContext request = RequestBuilder.Post()
                .WithHeader("X-Api-Key", "old")
                .ReceivedAt(expiry.AddHours(hoursFromExpiry))
                .Build();

            AuthResult result = new SharedSecretAuthenticator(provider, "X-Api-Key").Authenticate(request);

            Assert.Equal(accepted, result.Succeeded);
            Assert.Equal(accepted ? string.Empty : AuthFailureCode.CredentialMismatch, result.FailureCode);
        }

        [Fact]
        public void RepeatedHeader_AuthenticatesWhenAnyValueMatches()
        {
            WebhookAuthContext request = RequestBuilder.Post()
                .WithRepeatedHeader("X-Api-Key", "wrong", "s3cret")
                .Build();

            Assert.True(Authenticator("s3cret").Authenticate(request).Succeeded);
        }

        [Fact]
        public void BlankHeaderName_ThrowsAtConstruction()
        {
            var provider = new StaticSecretProvider(WebhookSecret.FromUtf8("x"));

            Assert.Throws<ArgumentException>(() => new SharedSecretAuthenticator(provider, " "));
        }
    }
}
