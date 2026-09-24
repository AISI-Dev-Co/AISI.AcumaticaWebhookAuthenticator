// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Text;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using AISI.AcumaticaWebhookAuthenticator.Signing;
using Xunit;

namespace AISI.AcumaticaWebhookAuthenticator.Tests
{
    public class SecretEncodingTests
    {
        private static readonly byte[] Key = { 0xDE, 0xAD, 0xBE, 0xEF };
        private static readonly byte[] Message = Encoding.UTF8.GetBytes("Hello, World!");

        [Theory]
        [InlineData("deadbeef", SecretEncoding.Hex)]
        [InlineData("3q2+7w==", SecretEncoding.Base64)]
        [InlineData("whsec_3q2+7w==", SecretEncoding.StandardWebhooks)]
        [InlineData("3q2+7w==", SecretEncoding.StandardWebhooks)]
        public void ParseDecodesEachEncodingToTheSameKey(string text, SecretEncoding encoding)
        {
            Assert.True(Matches(WebhookSecret.Parse(text, encoding), Key));
        }

        [Fact]
        public void Utf8UsesTheTextItself()
        {
            Assert.True(Matches(WebhookSecret.Parse("deadbeef", SecretEncoding.Utf8), Encoding.UTF8.GetBytes("deadbeef")));
        }

        [Theory]
        [InlineData("not hex", SecretEncoding.Hex)]
        [InlineData("abc", SecretEncoding.Hex)]
        [InlineData("not base64!", SecretEncoding.Base64)]
        [InlineData("", SecretEncoding.Base64)]
        [InlineData("whsec_", SecretEncoding.StandardWebhooks)]
        [InlineData("whsec_not base64!", SecretEncoding.StandardWebhooks)]
        public void ParseRejectsTextInvalidForTheEncoding(string text, SecretEncoding encoding)
        {
            Assert.Throws<FormatException>(() => WebhookSecret.Parse(text, encoding));
        }

        [Fact]
        public void ParseRejectsAnUndefinedEncoding()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => WebhookSecret.Parse("x", (SecretEncoding)99));
        }

        [Fact]
        public void TheRotatingSecretIsDecodedUnderItsEncoding()
        {
            WebhookSecret secret = WebhookSecret
                .Parse("whsec_AAAAAAAAAAAAAAAAAAAAAA==", SecretEncoding.StandardWebhooks)
                .WithRotating("whsec_3q2+7w==", SecretEncoding.StandardWebhooks, DateTimeOffset.UnixEpoch.AddDays(1));

            Assert.True(Matches(secret, Key));
        }

        [Fact]
        public void StandardWebhooksReferenceVectorVerifies()
        {
            WebhookSecret secret = WebhookSecret.Parse("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw", SecretEncoding.StandardWebhooks);
            byte[] signed = Encoding.UTF8.GetBytes("msg_p5jXN8AQM9LWM0D4loKWxJek.1614265330.{\"test\": 2432232314}");
            byte[] expected = Convert.FromBase64String("g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=");

            Assert.True(secret.Matches(HmacAlgorithm.Sha256, signed, expected, DateTimeOffset.UnixEpoch));
        }

        [Theory]
        [InlineData(SecretEncoding.Utf8)]
        [InlineData(SecretEncoding.Base64)]
        [InlineData(SecretEncoding.Hex)]
        [InlineData(SecretEncoding.StandardWebhooks)]
        public void GeneratedSecretsParseUnderTheirEncoding(SecretEncoding encoding)
        {
            string generated = SecretGenerator.Generate(encoding);

            WebhookSecret.Parse(generated, encoding);
            Assert.True(generated.Length <= 255);
        }

        [Fact]
        public void GeneratedStandardWebhooksSecretsCarryThePrefix()
        {
            Assert.StartsWith(WebhookSecret.StandardWebhooksPrefix, SecretGenerator.Generate(SecretEncoding.StandardWebhooks), StringComparison.Ordinal);
        }

        [Fact]
        public void GeneratedSecretsDiffer()
        {
            Assert.NotEqual(SecretGenerator.Generate(SecretEncoding.Hex), SecretGenerator.Generate(SecretEncoding.Hex));
        }

        [Fact]
        public void GeneratedSecretsHaveTheRequestedStrength()
        {
            Assert.Equal(64, SecretGenerator.Generate(SecretEncoding.Hex, 32).Length);
            Assert.Throws<ArgumentOutOfRangeException>(() => SecretGenerator.Generate(SecretEncoding.Hex, SecretGenerator.MinByteLength - 1));
        }

        private static bool Matches(WebhookSecret secret, byte[] key) =>
            secret.Matches(HmacAlgorithm.Sha256, Message, HmacComputer.Compute(HmacAlgorithm.Sha256, key, Message), DateTimeOffset.UnixEpoch);
    }
}
