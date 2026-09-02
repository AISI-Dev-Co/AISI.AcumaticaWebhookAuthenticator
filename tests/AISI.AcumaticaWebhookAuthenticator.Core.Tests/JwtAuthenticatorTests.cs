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
        private static readonly string EmptyBodyBh =
            JwtAuthenticator.Base64UrlEncode(JwtAuthenticator.ComputeBodyHash(Array.Empty<byte>()));
        private static readonly string DefaultAud = RequestBuilder.DefaultWebhookId.ToString("D");

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
            return "{\"exp\":" + exp +
                ",\"aud\":\"" + DefaultAud + "\"" +
                ",\"bh\":\"" + EmptyBodyBh + "\"" +
                extra + "}";
        }

        private static string Sign(string headerJson, string payloadJson, byte[]? key = null)
        {
            string header = JwtAuthenticator.Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
            string payload = JwtAuthenticator.Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
            byte[] signature = HmacComputer.Compute(
                HmacAlgorithm.Sha256,
                key ?? SecretBytes,
                Encoding.ASCII.GetBytes(header + "." + payload));
            return header + "." + payload + "." + JwtAuthenticator.Base64UrlEncode(signature);
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
        public void InvalidUtf8Header_IsJwtMalformed()
        {
            string header = JwtAuthenticator.Base64UrlEncode(new byte[] { 0xFF, 0xFE });
            string payload = JwtAuthenticator.Base64UrlEncode(Encoding.UTF8.GetBytes("{}"));
            string jwt = header + "." + payload + ".e30";
            WebhookAuthContext request = RequestBuilder.Post()
                .ReceivedAt(Now)
                .WithHeader("Authorization", "Bearer " + jwt)
                .Build();

            AuthResult result = Bearer().Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.JwtMalformed, result.FailureCode);
        }

        [Fact]
        public void Rfc7515AppendixA1_Hs256Vector_Authenticates()
        {
            // RFC 7515 appendix A.1 has no bh/aud. This is a JOSE vector, not a product sample.
            // Unbound flags stay on this test only — first sample is JwtBearer() defaults (bh+aud).
            const string jwt =
                "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9." +
                "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
            const string keyB64Url =
                "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";

            string padded = keyB64Url.Replace('-', '+').Replace('_', '/');
            switch (padded.Length % 4)
            {
                case 2:
                    padded += "==";
                    break;
                case 3:
                    padded += "=";
                    break;
            }

            byte[] key = Convert.FromBase64String(padded);
            var authenticator = new JwtAuthenticator(
                new JwtAuthOptions(new StaticSecretProvider(WebhookSecret.FromBytes(key)))
                {
                    RequireBodyHash = false,
                    BindAudienceToWebhookId = false,
                });

            WebhookAuthContext request = RequestBuilder.Post()
                .ReceivedAt(DateTimeOffset.FromUnixTimeSeconds(1_300_819_300))
                .WithHeader("Authorization", "Bearer " + jwt)
                .Build();

            Assert.True(authenticator.Authenticate(request).Succeeded);
        }

        [Fact]
        public void ValidJwt_TamperedBody_FailsWhenBodyBound()
        {
            byte[] original = Encoding.UTF8.GetBytes("{\"ok\":true}");
            string bh = JwtAuthenticator.Base64UrlEncode(JwtAuthenticator.ComputeBodyHash(original));
            long exp = Now.ToUnixTimeSeconds() + 3600;
            string jwt = Token(
                "{\"exp\":" + exp + ",\"aud\":\"" + DefaultAud + "\",\"bh\":\"" + bh + "\"}");

            WebhookAuthContext request = RequestBuilder.Post()
                .WithBody("tampered")
                .ReceivedAt(Now)
                .WithHeader("Authorization", "Bearer " + jwt)
                .Build();

            AuthResult result = Bearer().Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.JwtBodyHashMismatch, result.FailureCode);
        }

        [Fact]
        public void OverflowExp_IsUnauthorizedRatherThanThrown()
        {
            string jwt = Token(
                "{\"exp\":" + long.MaxValue +
                ",\"aud\":\"" + DefaultAud + "\",\"bh\":\"" + EmptyBodyBh + "\"}");
            WebhookAuthContext request = RequestBuilder.Post()
                .ReceivedAt(Now)
                .WithHeader("Authorization", "Bearer " + jwt)
                .Build();

            AuthResult result = Bearer().Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.JwtMalformed, result.FailureCode);
        }

        [Fact]
        public void EmptySignatureWithHs256_IsRejected()
        {
            string jwt = Token(FutureExpPayload());
            string[] parts = jwt.Split('.');
            string emptySig = parts[0] + "." + parts[1] + ".";
            WebhookAuthContext request = RequestBuilder.Post()
                .ReceivedAt(Now)
                .WithHeader("Authorization", "Bearer " + emptySig)
                .Build();

            AuthResult result = Bearer().Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.JwtMalformed, result.FailureCode);
        }

        [Fact]
        public void CritHeader_IsRejected()
        {
            string jwt = Sign(
                "{\"alg\":\"HS256\",\"typ\":\"JWT\",\"crit\":[\"b64\"]}",
                FutureExpPayload());
            WebhookAuthContext request = RequestBuilder.Post()
                .ReceivedAt(Now)
                .WithHeader("Authorization", "Bearer " + jwt)
                .Build();

            AuthResult result = Bearer().Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.JwtCriticalHeader, result.FailureCode);
        }

        [Fact]
        public void DuplicateAlgKey_IsRejected()
        {
            string jwt = Sign(
                "{\"alg\":\"HS256\",\"alg\":\"none\"}",
                FutureExpPayload());
            WebhookAuthContext request = RequestBuilder.Post()
                .ReceivedAt(Now)
                .WithHeader("Authorization", "Bearer " + jwt)
                .Build();

            AuthResult result = Bearer().Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.JwtMalformed, result.FailureCode);
        }

        [Fact]
        public void UnhandledJsonEscape_IsRejected()
        {
            string jwt = Sign(
                "{\"alg\":\"HS256\",\"x\":\"\\q\"}",
                FutureExpPayload());
            WebhookAuthContext request = RequestBuilder.Post()
                .ReceivedAt(Now)
                .WithHeader("Authorization", "Bearer " + jwt)
                .Build();

            AuthResult result = Bearer().Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.JwtMalformed, result.FailureCode);
        }

        [Fact]
        public void OversizedToken_IsRejected()
        {
            var padding = new string('a', 9000);
            string jwt = Token(
                "{\"exp\":" + (Now.ToUnixTimeSeconds() + 3600) +
                ",\"aud\":\"" + DefaultAud + "\",\"bh\":\"" + EmptyBodyBh +
                "\",\"pad\":\"" + padding + "\"}");
            WebhookAuthContext request = RequestBuilder.Post()
                .ReceivedAt(Now)
                .WithHeader("Authorization", "Bearer " + jwt)
                .Build();

            AuthResult result = Bearer().Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.JwtMalformed, result.FailureCode);
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
            string jwt = Token(
                "{\"exp\":" + exp + ",\"aud\":\"" + DefaultAud + "\",\"bh\":\"" + EmptyBodyBh + "\"}");
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
            string jwt = Token(
                "{\"exp\":" + exp + ",\"aud\":\"" + DefaultAud + "\",\"bh\":\"" + EmptyBodyBh + "\"}");
            WebhookAuthContext request = RequestBuilder.Post()
                .ReceivedAt(Now)
                .WithHeader("Authorization", "Bearer " + jwt)
                .Build();

            Assert.True(Bearer().Authenticate(request).Succeeded);
        }

        [Fact]
        public void MissingExp_FailsWhenRequired()
        {
            string jwt = Token("{\"sub\":\"x\",\"aud\":\"" + DefaultAud + "\",\"bh\":\"" + EmptyBodyBh + "\"}");
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
            string jwt = Token("{\"sub\":\"x\",\"aud\":\"" + DefaultAud + "\",\"bh\":\"" + EmptyBodyBh + "\"}");
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
            string jwt = Token(
                "{\"exp\":" + exp + ",\"nbf\":" + nbf +
                ",\"aud\":\"" + DefaultAud + "\",\"bh\":\"" + EmptyBodyBh + "\"}");
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
            long exp = Now.ToUnixTimeSeconds() + 3600;
            string jwt = Token(
                "{\"exp\":" + exp +
                ",\"iss\":\"sender\",\"aud\":[\"hook\",\"other\"],\"bh\":\"" + EmptyBodyBh + "\"}");
            WebhookAuthContext request = RequestBuilder.Post()
                .ReceivedAt(Now)
                .WithHeader("Authorization", "Bearer " + jwt)
                .Build();

            Assert.True(Bearer(o =>
            {
                o.Issuer = "sender";
                o.Audience = "hook";
            }).Authenticate(request).Succeeded);

            AuthResult badIss = Bearer(o =>
            {
                o.Issuer = "other";
                o.Audience = "hook";
            }).Authenticate(request);
            Assert.Equal(AuthFailureCode.JwtIssuerMismatch, badIss.FailureCode);

            AuthResult badAud = Bearer(o => o.Audience = "missing").Authenticate(request);
            Assert.Equal(AuthFailureCode.JwtAudienceMismatch, badAud.FailureCode);
        }

        [Fact]
        public void MissingWebhookId_FailsAudienceWhenBound()
        {
            string jwt = Token(FutureExpPayload());
            WebhookAuthContext request = RequestBuilder.Post()
                .WithoutWebhookId()
                .ReceivedAt(Now)
                .WithHeader("Authorization", "Bearer " + jwt)
                .Build();

            AuthResult result = Bearer().Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.JwtAudienceMismatch, result.FailureCode);
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
        public void UnboundedClockSkew_IsRejectedAtConstruction()
        {
            var options = new JwtAuthOptions(new StaticSecretProvider(WebhookSecret.FromUtf8(SecretText)))
            {
                ClockSkew = TimeSpan.FromDays(365),
            };

            Assert.Throws<ArgumentException>(() => new JwtAuthenticator(options));
        }

        [Fact]
        public void Preset_IsBearerHs256BoundToWebhookAndBody()
        {
            JwtAuthOptions options = WebhookAuthPresets.JwtBearer(
                new StaticSecretProvider(WebhookSecret.FromUtf8(SecretText)));

            Assert.Equal("Authorization", options.TokenHeader);
            Assert.Equal("Bearer ", options.SchemePrefix);
            Assert.Equal(HmacAlgorithm.Sha256, options.Algorithm);
            Assert.True(options.BindAudienceToWebhookId);
            Assert.True(options.RequireBodyHash);
            Assert.True(options.RequireExpiration);
        }

        [Fact]
        public void Challenge_IsRfc6750Bearer()
        {
            Assert.Equal("Bearer realm=\"webhook\"", Bearer().Challenge);
        }

        [Fact]
        public void Challenge_MatchesCustomHeaderWhenThereIsNoSchemePrefix()
        {
            var options = new JwtAuthOptions(
                new StaticSecretProvider(WebhookSecret.FromUtf8(SecretText)),
                "X-Webhook-Token")
            {
                SchemePrefix = null,
            };

            Assert.Equal("X-Webhook-Token realm=\"webhook\"", new JwtAuthenticator(options).Challenge);
        }
    }
}
