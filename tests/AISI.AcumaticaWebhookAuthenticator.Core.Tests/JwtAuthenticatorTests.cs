// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
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
        private static readonly long FutureExp = Now.AddHours(1).ToUnixTimeSeconds();
        private static readonly string EmptyBodyBh = JwtTestTokens.BodyHash(Array.Empty<byte>());
        private static readonly string DefaultAud = RequestBuilder.DefaultWebhookId.ToString("D");
        private static readonly long DefaultSkewSeconds = (long)Options().ClockSkew.TotalSeconds;

        #region Helpers
        private static StaticSecretProvider Provider() => new(WebhookSecret.FromUtf8(SecretText));

        private static JwtAuthOptions Options(Action<JwtAuthOptions>? configure = null)
        {
            var options = new JwtAuthOptions(Provider());
            configure?.Invoke(options);
            return options;
        }

        private static JwtAuthenticator Bearer(Action<JwtAuthOptions>? configure = null) => new(Options(configure));

        /// <summary>The bound default claims (exp, aud, bh) with overrides; a null value removes the claim.</summary>
        private static string Claims(params (string Name, object? Value)[] overrides)
        {
            var claims = new Dictionary<string, object?>
            {
                ["exp"] = FutureExp,
                ["aud"] = DefaultAud,
                ["bh"] = EmptyBodyBh,
            };

            foreach ((string name, object? value) in overrides)
            {
                if (value is null)
                {
                    claims.Remove(name);
                }
                else
                {
                    claims[name] = value;
                }
            }

            return JsonSerializer.Serialize(claims);
        }

        private static string Token(string payloadJson, HmacAlgorithm algorithm = HmacAlgorithm.Sha256, byte[]? key = null) =>
            JwtTestTokens.Compact(algorithm, key ?? SecretBytes, payloadJson);

        private static string SignedWithHeader(string headerJson) =>
            JwtTestTokens.Sign(headerJson, Claims(), SecretBytes);

        private static RequestBuilder Request(string authorization) =>
            RequestBuilder.Post().ReceivedAt(Now).WithHeader("Authorization", authorization);

        private static AuthResult Authenticate(string jwt, Action<JwtAuthOptions>? configure = null) =>
            Bearer(configure).Authenticate(Request("Bearer " + jwt).Build());

        private static void AssertFailure(string expectedFailure, AuthResult result)
        {
            Assert.False(result.Succeeded);
            Assert.Equal(expectedFailure, result.FailureCode);
        }

        private static void AssertOutcome(string? expectedFailure, AuthResult result)
        {
            if (expectedFailure is null)
            {
                Assert.True(result.Succeeded, result.FailureCode);
            }
            else
            {
                AssertFailure(expectedFailure, result);
            }
        }
        #endregion

        #region Signature and algorithm
        [Fact]
        public void ValidHs256Bearer_Authenticates()
        {
            Assert.True(Authenticate(Token(Claims())).Succeeded);
        }

        [Fact]
        public void Rfc7515AppendixA1_Hs256Vector_Authenticates()
        {
            const string jwt =
                "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9." +
                "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
            const string key = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ+EstJQLr/T+1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow==";

            // The RFC vector carries no bh or aud, so binding is off for it alone.
            var authenticator = new JwtAuthenticator(
                new JwtAuthOptions(new StaticSecretProvider(WebhookSecret.FromBase64(key)))
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
        public void WrongSecret_FailsAsSignatureMismatch()
        {
            string jwt = Token(Claims(), key: Encoding.UTF8.GetBytes("other-secret"));

            AssertFailure(AuthFailureCode.SignatureMismatch, Authenticate(jwt));
        }

        [Fact]
        public void TamperedPayload_FailsAsSignatureMismatch()
        {
            string[] parts = Token(Claims()).Split('.');
            string tampered = parts[0] + "." + JwtTestTokens.Base64Url("{\"exp\":9999999999}") + "." + parts[2];

            AssertFailure(AuthFailureCode.SignatureMismatch, Authenticate(tampered));
        }

        [Fact]
        public void EmptySignature_IsRejected()
        {
            string jwt = Token(Claims());

            AssertFailure(AuthFailureCode.JwtMalformed, Authenticate(jwt.Substring(0, jwt.LastIndexOf('.') + 1)));
        }

        [Fact]
        public void RotatingSecret_IsAcceptedInsideItsWindow()
        {
            string jwt = Token(Claims(), key: Encoding.UTF8.GetBytes("old-secret"));
            var provider = new StaticSecretProvider(
                WebhookSecret.FromUtf8(SecretText).WithRotatingUtf8("old-secret", Now.AddDays(1)));

            Assert.True(new JwtAuthenticator(new JwtAuthOptions(provider)).Authenticate(Request("Bearer " + jwt).Build()).Succeeded);
        }

        [Fact]
        public void AlgNone_IsRejected()
        {
            string jwt = JwtTestTokens.Base64Url("{\"alg\":\"none\",\"typ\":\"JWT\"}") + "." + JwtTestTokens.Base64Url(Claims()) + ".";

            AssertFailure(AuthFailureCode.JwtAlgorithmRejected, Authenticate(jwt));
        }

        [Fact]
        public void Hs512_WhenConfiguredForHs256_IsRejected()
        {
            AssertFailure(AuthFailureCode.JwtAlgorithmRejected, Authenticate(Token(Claims(), HmacAlgorithm.Sha512)));
        }

        [Fact]
        public void Hs512_AuthenticatesWhenConfigured()
        {
            Assert.True(Authenticate(Token(Claims(), HmacAlgorithm.Sha512), o => o.Algorithm = HmacAlgorithm.Sha512).Succeeded);
        }

        [Fact]
        public void CritHeader_IsRejected()
        {
            string jwt = SignedWithHeader("{\"alg\":\"HS256\",\"typ\":\"JWT\",\"crit\":[\"b64\"]}");

            AssertFailure(AuthFailureCode.JwtCriticalHeader, Authenticate(jwt));
        }
        #endregion

        #region Token parsing
        [Fact]
        public void DuplicateAlgKey_IsRejected()
        {
            AssertFailure(AuthFailureCode.JwtMalformed, Authenticate(SignedWithHeader("{\"alg\":\"HS256\",\"alg\":\"none\"}")));
        }

        [Fact]
        public void DuplicatePayloadKeys_AreRejected()
        {
            string payload = Claims().Replace("{\"exp\"", "{\"exp\":1,\"exp\"", StringComparison.Ordinal);

            AssertFailure(AuthFailureCode.JwtMalformed, Authenticate(Token(payload)));
        }

        [Fact]
        public void UnhandledJsonEscape_IsRejected()
        {
            AssertFailure(AuthFailureCode.JwtMalformed, Authenticate(SignedWithHeader("{\"alg\":\"HS256\",\"x\":\"\\q\"}")));
        }

        [Theory]
        [InlineData("{ \"alg\" :\t\"HS256\"\r\n}", null)]
        [InlineData("{\"alg\":\"HS256\",\u00A0\"typ\":\"JWT\"}", AuthFailureCode.JwtMalformed)]
        public void OnlyJsonWhitespace_IsAccepted(string headerJson, string? expectedFailure)
        {
            AssertOutcome(expectedFailure, Authenticate(SignedWithHeader(headerJson)));
        }

        [Fact]
        public void InvalidUtf8InsideHeaderString_IsJwtMalformed()
        {
            // Replacement decoding would turn 0xFF into U+FFFD and accept the token.
            byte[] header = Encoding.ASCII.GetBytes("{\"alg\":\"HS256\",\"x\":\"#\"}");
            header[Array.IndexOf(header, (byte)'#')] = 0xFF;
            string jwt = JwtTestTokens.SignSegments(
                JwtTestTokens.Base64Url(header), JwtTestTokens.Base64Url(Claims()), SecretBytes);

            AssertFailure(AuthFailureCode.JwtMalformed, Authenticate(jwt));
        }

        [Theory]
        [InlineData("{\"a\":", "}", JwtJsonObject.MaxDepth - 1, null)]
        [InlineData("{\"a\":", "}", JwtJsonObject.MaxDepth, AuthFailureCode.JwtMalformed)]
        [InlineData("{\"a\":", "}", 5000, AuthFailureCode.JwtMalformed)]
        [InlineData("[", "]", JwtJsonObject.MaxDepth - 1, null)]
        [InlineData("[", "]", 5000, AuthFailureCode.JwtMalformed)]
        public void HeaderNesting_IsCappedAtMaxDepth(string open, string close, int levels, string? expectedFailure)
        {
            string nested = string.Concat(Enumerable.Repeat(open, levels)) + "1" + string.Concat(Enumerable.Repeat(close, levels));
            string jwt = SignedWithHeader("{\"alg\":\"HS256\",\"x\":" + nested + "}");

            AssertOutcome(expectedFailure, Authenticate(jwt, o => o.MaxTokenLength = int.MaxValue));
        }

        [Fact]
        public void NonStringArrayClaim_DoesNotFailTheParse()
        {
            string jwt = Token(Claims(("roles", new object?[] { 1, null, new Dictionary<string, bool> { ["admin"] = true } })));

            Assert.True(Authenticate(jwt).Succeeded);
        }

        [Fact]
        public void AudienceArrayWithNonString_IsAudienceMismatch()
        {
            string jwt = Token(Claims(("aud", new object?[] { DefaultAud, null })));

            AssertFailure(AuthFailureCode.JwtAudienceMismatch, Authenticate(jwt));
        }

        [Fact]
        public void OversizedToken_IsRejected()
        {
            string jwt = Token(Claims(("pad", new string('a', JwtAuthOptions.DefaultMaxTokenLength))));

            AssertFailure(AuthFailureCode.JwtMalformed, Authenticate(jwt));
        }

        [Fact]
        public void OverflowExp_IsUnauthorizedRatherThanThrown()
        {
            AssertFailure(AuthFailureCode.JwtMalformed, Authenticate(Token(Claims(("exp", long.MaxValue)))));
        }
        #endregion

        #region Claims
        [Theory]
        [InlineData(-2.0, AuthFailureCode.JwtExpired)]
        [InlineData(-1.0, null)]
        [InlineData(-0.5, null)]
        public void Expiry_AllowsClockSkew(double skews, string? expectedFailure)
        {
            long exp = Now.ToUnixTimeSeconds() + (long)(DefaultSkewSeconds * skews);

            AssertOutcome(expectedFailure, Authenticate(Token(Claims(("exp", exp)))));
        }

        [Theory]
        [InlineData(true, AuthFailureCode.JwtExpirationMissing)]
        [InlineData(false, null)]
        public void MissingExp_FailsOnlyWhenRequired(bool required, string? expectedFailure)
        {
            string jwt = Token(Claims(("exp", null), ("sub", "x")));

            AssertOutcome(expectedFailure, Authenticate(jwt, o => o.RequireExpiration = required));
        }

        [Fact]
        public void NbfInTheFuture_Fails()
        {
            string jwt = Token(Claims(("nbf", Now.ToUnixTimeSeconds() + (2 * DefaultSkewSeconds))));

            AssertFailure(AuthFailureCode.JwtNotYetValid, Authenticate(jwt));
        }

        [Fact]
        public void IssuerAndAudience_MustMatchWhenConfigured()
        {
            string[] audiences = { "hook", "other" };
            string jwt = Token(Claims(("iss", "sender"), ("aud", audiences)));

            Assert.True(Authenticate(jwt, o =>
            {
                o.Issuer = "sender";
                o.Audience = "hook";
            }).Succeeded);

            AssertFailure(AuthFailureCode.JwtIssuerMismatch, Authenticate(jwt, o =>
            {
                o.Issuer = "other";
                o.Audience = "hook";
            }));

            AssertFailure(AuthFailureCode.JwtAudienceMismatch, Authenticate(jwt, o => o.Audience = "missing"));
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void MissingWebhookId_FailsAudienceWhenBound(bool emptyAudience)
        {
            string jwt = Token(Claims(("aud", emptyAudience ? string.Empty : DefaultAud)));
            WebhookAuthContext request = Request("Bearer " + jwt).WithoutWebhookId().Build();

            AssertFailure(AuthFailureCode.JwtAudienceMismatch, Bearer().Authenticate(request));
        }

        [Fact]
        public void TamperedBody_FailsAsBodyHashMismatch()
        {
            string jwt = Token(Claims(("bh", JwtTestTokens.BodyHash(Encoding.UTF8.GetBytes("{\"ok\":true}")))));
            WebhookAuthContext request = Request("Bearer " + jwt).WithBody("tampered").Build();

            AssertFailure(AuthFailureCode.JwtBodyHashMismatch, Bearer().Authenticate(request));
        }

        [Fact]
        public void MissingBodyHash_FailsUnderDefaultPreset()
        {
            var authenticator = new JwtAuthenticator(WebhookAuthPresets.JwtBearer(Provider()));
            WebhookAuthContext request = Request("Bearer " + Token(Claims(("bh", null)))).Build();

            AssertFailure(AuthFailureCode.JwtBodyHashMissing, authenticator.Authenticate(request));
        }
        #endregion

        #region Credential and secret handling
        [Fact]
        public void SchemeToken_IsCaseInsensitive()
        {
            Assert.True(Bearer().Authenticate(Request("bearer " + Token(Claims())).Build()).Succeeded);
        }

        [Fact]
        public void MissingHeader_FailsClosed()
        {
            AssertFailure(AuthFailureCode.CredentialMissing, Bearer().Authenticate(RequestBuilder.Post().ReceivedAt(Now).Build()));
        }

        [Theory]
        [InlineData("Basic abc", AuthFailureCode.CredentialMalformed)]
        [InlineData("Bearer", AuthFailureCode.CredentialMalformed)]
        [InlineData("Bearer ", AuthFailureCode.CredentialMalformed)]
        [InlineData("not-a-jwt", AuthFailureCode.CredentialMalformed)]
        [InlineData("Bearer not-a-jwt", AuthFailureCode.JwtMalformed)]
        public void MalformedCredential_FailsWithoutThrowing(string headerValue, string expectedFailure)
        {
            AssertFailure(expectedFailure, Bearer().Authenticate(Request(headerValue).Build()));
        }

        [Fact]
        public void NullSecret_FailsClosed()
        {
            var authenticator = new JwtAuthenticator(new JwtAuthOptions(new NullSecretProvider()));

            AssertFailure(AuthFailureCode.SecretUnavailable, authenticator.Authenticate(Request("Bearer " + Token(Claims())).Build()));
        }

        [Fact]
        public void SecretProviderException_Propagates()
        {
            var authenticator = new JwtAuthenticator(new JwtAuthOptions(new ThrowingSecretProvider()));
            WebhookAuthContext request = Request("Bearer " + Token(Claims())).Build();

            Assert.Throws<InvalidOperationException>(() => authenticator.Authenticate(request));
        }
        #endregion

        #region Configuration and challenge
        [Theory]
        [InlineData("HS1")]
        [InlineData("negative skew")]
        [InlineData("skew over max")]
        [InlineData("token cap under min")]
        [InlineData("quote in token header")]
        [InlineData("control character in scheme prefix")]
        public void Misconfiguration_IsRejectedAtConstruction(string misconfiguration)
        {
            JwtAuthOptions options = misconfiguration switch
            {
                "HS1" => Options(o => o.Algorithm = HmacAlgorithm.Sha1),
                "negative skew" => Options(o => o.ClockSkew = TimeSpan.FromSeconds(-1)),
                "skew over max" => Options(o => o.ClockSkew = JwtAuthOptions.MaxClockSkew + TimeSpan.FromSeconds(1)),
                "token cap under min" => Options(o => o.MaxTokenLength = JwtAuthOptions.MinTokenLength - 1),
                "quote in token header" => new JwtAuthOptions(Provider(), "X-\"Token"),
                "control character in scheme prefix" => Options(o => o.SchemePrefix = "Bearer\r\n"),
                _ => throw new ArgumentOutOfRangeException(nameof(misconfiguration)),
            };

            Assert.Throws<ArgumentException>(() => new JwtAuthenticator(options));
        }

        [Fact]
        public void Challenge_IsRfc6750Bearer()
        {
            Assert.Equal("Bearer realm=\"webhook\"", Bearer().Challenge);
        }

        [Fact]
        public void Challenge_MatchesCustomHeaderWhenThereIsNoSchemePrefix()
        {
            var options = new JwtAuthOptions(Provider(), "X-Webhook-Token")
            {
                SchemePrefix = null,
            };

            Assert.Equal("X-Webhook-Token realm=\"webhook\"", new JwtAuthenticator(options).Challenge);
        }
        #endregion

        private sealed class ThrowingSecretProvider : IWebhookSecretProvider
        {
            public WebhookSecret? GetSecret() => throw new InvalidOperationException("Secret store unreachable.");
        }
    }
}
