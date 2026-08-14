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

        [Fact]
        public void MatchingSecret_Authenticates()
        {
            WebhookAuthContext request = RequestBuilder.Post()
                .WithBody("{}")
                .WithHeader("X-Api-Key", "s3cret")
                .Build();

            Assert.True(Authenticator("s3cret").Authenticate(request).Succeeded);
        }

        [Fact]
        public void WrongSecret_FailsAsMismatch()
        {
            WebhookAuthContext request = RequestBuilder.Post()
                .WithHeader("X-Api-Key", "wrong")
                .Build();

            AuthResult result = Authenticator("s3cret").Authenticate(request);

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
            WebhookAuthContext request = RequestBuilder.Post().WithHeader("X-Api-Key", "anything").Build();

            AuthResult result = authenticator.Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.SecretUnavailable, result.FailureCode);
        }

        [Fact]
        public void Prefix_IsStrippedBeforeComparison()
        {
            WebhookAuthContext request = RequestBuilder.Post()
                .WithHeader("X-Api-Key", "Token s3cret")
                .Build();

            Assert.True(Authenticator("s3cret", "Token ").Authenticate(request).Succeeded);
        }

        [Fact]
        public void MissingPrefix_FailsAsMalformed()
        {
            WebhookAuthContext request = RequestBuilder.Post()
                .WithHeader("X-Api-Key", "s3cret")
                .Build();

            AuthResult result = Authenticator("s3cret", "Token ").Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.CredentialMalformed, result.FailureCode);
        }

        [Fact]
        public void SecretIsNotTreatedAsAPrefixMatch()
        {
            // "s3cret-and-more" starts with the secret; equality must be over the whole value.
            WebhookAuthContext request = RequestBuilder.Post()
                .WithHeader("X-Api-Key", "s3cret-and-more")
                .Build();

            Assert.False(Authenticator("s3cret").Authenticate(request).Succeeded);
        }

        [Fact]
        public void RotatingSecret_IsAcceptedInsideItsWindow()
        {
            var expiry = DateTimeOffset.UnixEpoch.AddDays(1);
            var provider = new StaticSecretProvider(
                WebhookSecret.FromUtf8("new").WithRotatingUtf8("old", expiry));
            var authenticator = new SharedSecretAuthenticator(provider, "X-Api-Key");

            WebhookAuthContext request = RequestBuilder.Post()
                .WithHeader("X-Api-Key", "old")
                .ReceivedAt(expiry.AddHours(-1))
                .Build();

            Assert.True(authenticator.Authenticate(request).Succeeded);
        }

        [Fact]
        public void RotatingSecret_IsRejectedAfterItsWindow()
        {
            var expiry = DateTimeOffset.UnixEpoch.AddDays(1);
            var provider = new StaticSecretProvider(
                WebhookSecret.FromUtf8("new").WithRotatingUtf8("old", expiry));
            var authenticator = new SharedSecretAuthenticator(provider, "X-Api-Key");

            WebhookAuthContext request = RequestBuilder.Post()
                .WithHeader("X-Api-Key", "old")
                .ReceivedAt(expiry.AddHours(1))
                .Build();

            AuthResult result = authenticator.Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.CredentialMismatch, result.FailureCode);
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

        [Fact]
        public void Code_ReportsSecret()
        {
            Assert.Equal("SECRET", Authenticator("x").Code);
        }

        private sealed class NullSecretProvider : IWebhookSecretProvider
        {
            public WebhookSecret? GetSecret() => null;
        }
    }
}
