// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Text;
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

        private static WebhookAuthContext Request(string authorization) =>
            RequestBuilder.Post().WithHeader("Authorization", authorization).Build();

        private static string Encode(string credential) => Convert.ToBase64String(Encoding.UTF8.GetBytes(credential));

        [Theory]
        [InlineData("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==")] // RFC 7617 §2
        [InlineData("bASIC QWxhZGRpbjpvcGVuIHNlc2FtZQ==")]
        [InlineData("Basic   QWxhZGRpbjpvcGVuIHNlc2FtZQ==")]
        public void Rfc7617Vector_Authenticates(string authorization)
        {
            Assert.True(Authenticator().Authenticate(Request(authorization)).Succeeded);
        }

        [Fact]
        public void WrongCredential_FailsAsMismatch()
        {
            AuthResult result = Authenticator().Authenticate(Request("Basic " + Encode("Aladdin:wrong")));

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
        [InlineData("Bearer QWxhZGRpbjpvcGVuIHNlc2FtZQ==")]
        [InlineData("Basic not-base64!!!")]
        [InlineData("Basic")]
        [InlineData("Basic ")]
        [InlineData("BasicQWxhZGRpbjpvcGVuIHNlc2FtZQ==")]
        public void MalformedCredential_FailsAsMalformedRatherThanThrowing(string authorization)
        {
            AuthResult result = Authenticator().Authenticate(Request(authorization));

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.CredentialMalformed, result.FailureCode);
        }

        [Fact]
        public void NullSecret_FailsClosed()
        {
            AuthResult result = new BasicAuthenticator(new NullSecretProvider())
                .Authenticate(Request("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="));

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.SecretUnavailable, result.FailureCode);
        }

        [Fact]
        public void RotatedCredential_IsAcceptedInsideItsWindow()
        {
            var expiry = DateTimeOffset.UnixEpoch.AddDays(1);
            var provider = new StaticSecretProvider(
                WebhookSecret.FromUtf8("svc:new").WithRotatingUtf8("svc:old", expiry));

            WebhookAuthContext request = RequestBuilder.Post()
                .WithHeader("Authorization", "Basic " + Encode("svc:old"))
                .ReceivedAt(expiry.AddHours(-1))
                .Build();

            Assert.True(new BasicAuthenticator(provider).Authenticate(request).Succeeded);
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
    }
}
