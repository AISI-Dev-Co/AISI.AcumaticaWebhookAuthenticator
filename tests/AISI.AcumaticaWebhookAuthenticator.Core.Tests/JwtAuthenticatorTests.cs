// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Text;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using AISI.AcumaticaWebhookAuthenticator.Diagnostics;
using AISI.AcumaticaWebhookAuthenticator.Signing;
using Xunit;

namespace AISI.AcumaticaWebhookAuthenticator.Tests
{
    public class JwtAuthenticatorTests
    {
        private const string SecretText = "test-secret";
        private static readonly byte[] SecretBytes = Encoding.UTF8.GetBytes(SecretText);
        private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);

        private static JwtAuthenticator Bearer(Action<JwtAuthOptions>? configure = null)
        {
            var options = new JwtAuthOptions(new StaticSecretProvider(WebhookSecret.FromUtf8(SecretText)));
            configure?.Invoke(options);
            return new JwtAuthenticator(options);
        }

        private static string Token(string payloadJson, HmacAlgorithm algorithm = HmacAlgorithm.Sha256, byte[]? key = null) =>
            JwtAuthenticator.Compact(algorithm, key ?? SecretBytes, payloadJson);

        private static string FutureExpPayload(string extra = "")
        {
            long exp = Now.ToUnixTimeSeconds() + 3600;
            return "{\"exp\":" + exp + extra + "}";
        }

        [Fact]
        public void ValidHs256Bearer_Authenticates()
        {
            string jwt = Token(FutureExpPayload());
            WebhookAuthContext request = RequestBuilder.Post()
                .ReceivedAt(Now)
                .WithHeader("Authorization", "Bearer " + jwt)
                .Build();

            Assert.True(Bearer().Authenticate(request).Succeeded);
        }

        [Fact]
        public void SchemeToken_IsCaseInsensitive()
        {
            string jwt = Token(FutureExpPayload());
            WebhookAuthContext request = RequestBuilder.Post()
                .ReceivedAt(Now)
                .WithHeader("Authorization", "bearer " + jwt)
                .Build();

            Assert.True(Bearer().Authenticate(request).Succeeded);
        }

        [Fact]
        public void WrongSecret_FailsAsSignatureMismatch()
        {
            string jwt = Token(FutureExpPayload());
            var authenticator = new JwtAuthenticator(
                new JwtAuthOptions(new StaticSecretProvider(WebhookSecret.FromUtf8("other-secret"))));
            WebhookAuthContext request = RequestBuilder.Post()
                .ReceivedAt(Now)
                .WithHeader("Authorization", "Bearer " + jwt)
                .Build();

            AuthResult result = authenticator.Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.SignatureMismatch, result.FailureCode);
        }

        [Fact]
        public void RotatingSecret_IsAcceptedInsideItsWindow()
        {
            string jwt = Token(FutureExpPayload(), key: Encoding.UTF8.GetBytes("old-secret"));
            var provider = new StaticSecretProvider(
                WebhookSecret.FromUtf8(SecretText).WithRotatingUtf8("old-secret", Now.AddDays(1)));
            var authenticator = new JwtAuthenticator(new JwtAuthOptions(provider));
            WebhookAuthContext request = RequestBuilder.Post()
                .ReceivedAt(Now)
                .WithHeader("Authorization", "Bearer " + jwt)
                .Build();

            Assert.True(authenticator.Authenticate(request).Succeeded);
        }

        [Fact]
        public void ExpiredToken_Fails()
        {
            long exp = Now.ToUnixTimeSeconds() - 120;
            string jwt = Token("{\"exp\":" + exp + "}");
            WebhookAuthContext request = RequestBuilder.Post()
                .ReceivedAt(Now)
                .WithHeader("Authorization", "Bearer " + jwt)
                .Build();

            AuthResult result = Bearer().Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.JwtExpired, result.FailureCode);
        }

        [Fact]
        public void ExpiredWithinClockSkew_Succeeds()
        {
            long exp = Now.ToUnixTimeSeconds() - 30;
            string jwt = Token("{\"exp\":" + exp + "}");
            WebhookAuthContext request = RequestBuilder.Post()
                .ReceivedAt(Now)
                .WithHeader("Authorization", "Bearer " + jwt)
                .Build();

            Assert.True(Bearer().Authenticate(request).Succeeded);
        }

        [Fact]
        public void MissingExp_FailsWhenRequired()
        {
            string jwt = Token("{\"sub\":\"x\"}");
            WebhookAuthContext request = RequestBuilder.Post()
                .ReceivedAt(Now)
                .WithHeader("Authorization", "Bearer " + jwt)
                .Build();

            AuthResult result = Bearer().Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.JwtExpirationMissing, result.FailureCode);
        }

        [Fact]
        public void MissingExp_SucceedsWhenNotRequired()
        {
            string jwt = Token("{\"sub\":\"x\"}");
            WebhookAuthContext request = RequestBuilder.Post()
                .ReceivedAt(Now)
                .WithHeader("Authorization", "Bearer " + jwt)
                .Build();

            Assert.True(Bearer(o => o.RequireExpiration = false).Authenticate(request).Succeeded);
        }

        [Fact]
        public void NbfInTheFuture_Fails()
        {
            long nbf = Now.ToUnixTimeSeconds() + 120;
            long exp = Now.ToUnixTimeSeconds() + 3600;
            string jwt = Token("{\"exp\":" + exp + ",\"nbf\":" + nbf + "}");
            WebhookAuthContext request = RequestBuilder.Post()
                .ReceivedAt(Now)
                .WithHeader("Authorization", "Bearer " + jwt)
                .Build();

            AuthResult result = Bearer().Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.JwtNotYetValid, result.FailureCode);
        }

        [Fact]
        public void IssuerAndAudience_MustMatchWhenConfigured()
        {
            string jwt = Token(FutureExpPayload(",\"iss\":\"sender\",\"aud\":[\"hook\",\"other\"]"));
            WebhookAuthContext request = RequestBuilder.Post()
                .ReceivedAt(Now)
                .WithHeader("Authorization", "Bearer " + jwt)
                .Build();

            Assert.True(Bearer(o =>
            {
                o.Issuer = "sender";
                o.Audience = "hook";
            }).Authenticate(request).Succeeded);

            AuthResult badIss = Bearer(o => o.Issuer = "other").Authenticate(request);
            Assert.Equal(AuthFailureCode.JwtIssuerMismatch, badIss.FailureCode);

            AuthResult badAud = Bearer(o => o.Audience = "missing").Authenticate(request);
            Assert.Equal(AuthFailureCode.JwtAudienceMismatch, badAud.FailureCode);
        }

        [Fact]
        public void AlgNone_IsRejected()
        {
            string header = JwtAuthenticator.Base64UrlEncode(Encoding.UTF8.GetBytes("{\"alg\":\"none\",\"typ\":\"JWT\"}"));
            string payload = JwtAuthenticator.Base64UrlEncode(Encoding.UTF8.GetBytes(FutureExpPayload()));
            string jwt = header + "." + payload + ".";
            WebhookAuthContext request = RequestBuilder.Post()
                .ReceivedAt(Now)
                .WithHeader("Authorization", "Bearer " + jwt)
                .Build();

            AuthResult result = Bearer().Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.JwtAlgorithmRejected, result.FailureCode);
        }

        [Fact]
        public void Hs512_WhenConfiguredForHs256_IsRejected()
        {
            string jwt = Token(FutureExpPayload(), HmacAlgorithm.Sha512);
            WebhookAuthContext request = RequestBuilder.Post()
                .ReceivedAt(Now)
                .WithHeader("Authorization", "Bearer " + jwt)
                .Build();

            AuthResult result = Bearer().Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.JwtAlgorithmRejected, result.FailureCode);
        }

        [Fact]
        public void Hs512_AuthenticatesWhenConfigured()
        {
            string jwt = Token(FutureExpPayload(), HmacAlgorithm.Sha512);
            WebhookAuthContext request = RequestBuilder.Post()
                .ReceivedAt(Now)
                .WithHeader("Authorization", "Bearer " + jwt)
                .Build();

            Assert.True(Bearer(o => o.Algorithm = HmacAlgorithm.Sha512).Authenticate(request).Succeeded);
        }

        [Fact]
        public void MissingHeader_FailsClosed()
        {
            AuthResult result = Bearer().Authenticate(RequestBuilder.Post().ReceivedAt(Now).Build());

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.CredentialMissing, result.FailureCode);
        }

        [Fact]
        public void NullSecret_FailsClosed()
        {
            var authenticator = new JwtAuthenticator(new JwtAuthOptions(new NullSecretProvider()));
            string jwt = Token(FutureExpPayload());
            WebhookAuthContext request = RequestBuilder.Post()
                .ReceivedAt(Now)
                .WithHeader("Authorization", "Bearer " + jwt)
                .Build();

            AuthResult result = authenticator.Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.SecretUnavailable, result.FailureCode);
        }

        [Theory]
        [InlineData("Basic abc")]
        [InlineData("Bearer")]
        [InlineData("Bearer ")]
        [InlineData("not-a-jwt")]
        public void MalformedCredential_DoesNotThrow(string headerValue)
        {
            WebhookAuthContext request = RequestBuilder.Post()
                .ReceivedAt(Now)
                .WithHeader("Authorization", headerValue)
                .Build();

            AuthResult result = Bearer().Authenticate(request);

            Assert.False(result.Succeeded);
        }

        [Fact]
        public void Sha1_IsRejectedAtConstruction()
        {
            var options = new JwtAuthOptions(new StaticSecretProvider(WebhookSecret.FromUtf8(SecretText)))
            {
                Algorithm = HmacAlgorithm.Sha1,
            };

            Assert.Throws<ArgumentException>(() => new JwtAuthenticator(options));
        }

        [Fact]
        public void Preset_IsBearerHs256()
        {
            JwtAuthOptions options = WebhookAuthPresets.JwtBearer(
                new StaticSecretProvider(WebhookSecret.FromUtf8(SecretText)));

            Assert.Equal("Authorization", options.TokenHeader);
            Assert.Equal("Bearer ", options.SchemePrefix);
            Assert.Equal(HmacAlgorithm.Sha256, options.Algorithm);
        }

        [Fact]
        public void Challenge_IsRfc6750Bearer()
        {
            Assert.Equal("Bearer realm=\"webhook\"", Bearer().Challenge);
        }
    }
}
