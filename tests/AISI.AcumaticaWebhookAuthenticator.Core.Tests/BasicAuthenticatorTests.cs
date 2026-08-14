// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using AISI.AcumaticaWebhookAuthenticator.Diagnostics;
using Xunit;

namespace AISI.AcumaticaWebhookAuthenticator.Tests
{
    public class BasicAuthenticatorTests
    {
        private static BasicAuthenticator Authenticator(string credential = "Aladdin:open sesame") =>
            new(new StaticSecretProvider(WebhookSecret.FromUtf8(credential)));

        [Fact]
        public void Rfc7617Vector_Authenticates()
        {
            // The user-id/password pair and its encoding are RFC 7617's own example (§2).
            WebhookAuthContext request = RequestBuilder.Post()
                .WithHeader("Authorization", "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==")
                .Build();

            Assert.True(Authenticator().Authenticate(request).Succeeded);
        }

        [Fact]
        public void SchemeToken_IsCaseInsensitive()
        {
            WebhookAuthContext request = RequestBuilder.Post()
                .WithHeader("Authorization", "bASIC QWxhZGRpbjpvcGVuIHNlc2FtZQ==")
                .Build();

            Assert.True(Authenticator().Authenticate(request).Succeeded);
        }

        [Fact]
        public void WrongCredential_FailsAsMismatch()
        {
            WebhookAuthContext request = RequestBuilder.Post()
                .WithHeader("Authorization", "Basic " + Convert.ToBase64String(
                    System.Text.Encoding.UTF8.GetBytes("Aladdin:wrong")))
                .Build();

            AuthResult result = Authenticator().Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.CredentialMismatch, result.FailureCode);
        }

        [Fact]
        public void MissingAuthorizationHeader_FailsAsCredentialMissing()
        {
            AuthResult result = Authenticator().Authenticate(RequestBuilder.Post().Build());

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.CredentialMissing, result.FailureCode);
        }

        [Theory]
        [InlineData("Bearer QWxhZGRpbjpvcGVuIHNlc2FtZQ==")] // wrong scheme
        [InlineData("Basic not-base64!!!")]
        [InlineData("Basic")]
        [InlineData("Basic ")]
        [InlineData("BasicQWxhZGRpbjpvcGVuIHNlc2FtZQ==")] // no separator
        public void MalformedCredential_FailsAsMalformedRatherThanThrowing(string headerValue)
        {
            WebhookAuthContext request = RequestBuilder.Post()
                .WithHeader("Authorization", headerValue)
                .Build();

            AuthResult result = Authenticator().Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.CredentialMalformed, result.FailureCode);
        }

        [Fact]
        public void NullSecret_FailsClosed()
        {
            var authenticator = new BasicAuthenticator(new NullSecretProvider());
            WebhookAuthContext request = RequestBuilder.Post()
                .WithHeader("Authorization", "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==")
                .Build();

            AuthResult result = authenticator.Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.SecretUnavailable, result.FailureCode);
        }

        [Fact]
        public void RotatedCredential_IsAcceptedInsideItsWindow()
        {
            var expiry = DateTimeOffset.UnixEpoch.AddDays(1);
            var provider = new StaticSecretProvider(
                WebhookSecret.FromUtf8("svc:new").WithRotatingUtf8("svc:old", expiry));
            var authenticator = new BasicAuthenticator(provider);

            WebhookAuthContext request = RequestBuilder.Post()
                .WithHeader("Authorization", "Basic " + Convert.ToBase64String(
                    System.Text.Encoding.UTF8.GetBytes("svc:old")))
                .ReceivedAt(expiry.AddHours(-1))
                .Build();

            Assert.True(authenticator.Authenticate(request).Succeeded);
        }

        [Fact]
        public void Challenge_CarriesTheRealm()
        {
            var authenticator = new BasicAuthenticator(
                new StaticSecretProvider(WebhookSecret.FromUtf8("a:b")), "erp-webhooks");

            Assert.Equal("Basic realm=\"erp-webhooks\", charset=\"UTF-8\"", authenticator.Challenge);
        }

        [Theory]
        [InlineData("")]
        [InlineData(" ")]
        [InlineData("has\"quote")]
        [InlineData("has\\backslash")]
        [InlineData("has\r\nnewline")]
        public void HostileRealm_ThrowsAtConstruction(string realm)
        {
            var provider = new StaticSecretProvider(WebhookSecret.FromUtf8("a:b"));

            Assert.Throws<ArgumentException>(() => new BasicAuthenticator(provider, realm));
        }

        [Fact]
        public void Code_ReportsBasic()
        {
            Assert.Equal("BASIC", Authenticator().Code);
        }

    }
}
