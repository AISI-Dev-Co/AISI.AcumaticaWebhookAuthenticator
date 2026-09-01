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
    public class JwtDuplicateKeyTests
    {
        private const string SecretText = "test-secret";
        private static readonly byte[] SecretBytes = Encoding.UTF8.GetBytes(SecretText);
        private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);
        private const char Quote = '"';

        private static string Quoted(string value) => Quote + value + Quote;

        private static string Member(string name, string value) => Quoted(name) + ":" + Quoted(value);

        private static string MemberNum(string name, long value) => Quoted(name) + ":" + value;

        private static string JsonObject(params string[] members) => "{" + string.Join(",", members) + "}";

        private static string EmptyBodyBh =>
            JwtAuthenticator.Base64UrlEncode(JwtAuthenticator.ComputeBodyHash(Array.Empty<byte>()));

        private static string DefaultAud => RequestBuilder.DefaultWebhookId.ToString("D");

        private static string BoundPayload() => JsonObject(
            MemberNum("exp", Now.ToUnixTimeSeconds() + 3600),
            Member("aud", DefaultAud),
            Member("bh", EmptyBodyBh));

        private static string Sign(string headerJson, string payloadJson)
        {
            string header = JwtAuthenticator.Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
            string payload = JwtAuthenticator.Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
            byte[] signature = HmacComputer.Compute(
                HmacAlgorithm.Sha256,
                SecretBytes,
                Encoding.ASCII.GetBytes(header + "." + payload));
            return header + "." + payload + "." + JwtAuthenticator.Base64UrlEncode(signature);
        }

        private static JwtAuthenticator Bearer() =>
            new JwtAuthenticator(new JwtAuthOptions(new StaticSecretProvider(WebhookSecret.FromUtf8(SecretText))));

        [Fact]
        public void DuplicateHeaderKeys_AreRejected()
        {
            string jwt = Sign(
                JsonObject(Member("alg", "HS256"), Member("typ", "JWT"), Member("typ", "JOSE")),
                BoundPayload());
            WebhookAuthContext request = RequestBuilder.Post()
                .ReceivedAt(Now)
                .WithHeader("Authorization", "Bearer " + jwt)
                .Build();

            AuthResult result = Bearer().Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.JwtMalformed, result.FailureCode);
        }

        [Fact]
        public void DuplicatePayloadKeys_AreRejected()
        {
            long exp = Now.ToUnixTimeSeconds() + 3600;
            string jwt = Sign(
                JsonObject(Member("alg", "HS256"), Member("typ", "JWT")),
                JsonObject(
                    MemberNum("exp", exp),
                    MemberNum("exp", 1),
                    Member("aud", DefaultAud),
                    Member("bh", EmptyBodyBh)));
            WebhookAuthContext request = RequestBuilder.Post()
                .ReceivedAt(Now)
                .WithHeader("Authorization", "Bearer " + jwt)
                .Build();

            AuthResult result = Bearer().Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.JwtMalformed, result.FailureCode);
        }
    }
}
