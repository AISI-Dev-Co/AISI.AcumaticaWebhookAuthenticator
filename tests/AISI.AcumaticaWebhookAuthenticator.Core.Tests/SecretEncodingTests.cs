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
        // Mirrors AISIWebhookSecret.SecretLength in the Acumatica DAC.
        private const int StoredSecretMaxLength = 255;

        private static readonly byte[] Key = { 0xDE, 0xAD, 0xBE, 0xEF };
        private static readonly byte[] Message = Encoding.UTF8.GetBytes("Hello, World!");
        private static readonly DateTimeOffset OverlapEnds = DateTimeOffset.UnixEpoch.AddDays(1);

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
        [InlineData(false)]
        [InlineData(true)]
        public void MutatingTheCallersKeyArrayDoesNotChangeTheSecret(bool asRotating)
        {
            byte[] key = (byte[])Key.Clone();
            WebhookSecret secret = asRotating
                ? WebhookSecret.FromBytes(new byte[] { 1 }).WithRotating(key, OverlapEnds)
                : WebhookSecret.FromBytes(key);

            Array.Clear(key, 0, key.Length);

            Assert.True(Matches(secret, Key));
        }

        [Theory]
        [InlineData("not hex", SecretEncoding.Hex)]
        [InlineData("abc", SecretEncoding.Hex)]
        [InlineData("not base64!", SecretEncoding.Base64)]
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

        [Theory]
        [InlineData("", SecretEncoding.Utf8)]
        [InlineData("", SecretEncoding.Hex)]
        [InlineData("", SecretEncoding.Base64)]
        [InlineData("   ", SecretEncoding.Base64)]
        [InlineData("whsec_", SecretEncoding.StandardWebhooks)]
        public void TextThatDecodesToAnEmptyKeyIsRejected(string text, SecretEncoding encoding)
        {
            WebhookSecret current = WebhookSecret.FromBytes(Key);

            Assert.Throws<FormatException>(() => WebhookSecret.Parse(text, encoding));
            Assert.Throws<FormatException>(() => current.WithRotating(text, encoding, OverlapEnds));
        }

        [Fact]
        public void AnEmptyKeyIsRejected()
        {
            WebhookSecret current = WebhookSecret.FromBytes(Key);

            Assert.Throws<ArgumentException>(() => WebhookSecret.FromBytes(Array.Empty<byte>()));
            Assert.Throws<ArgumentException>(() => current.WithRotating(Array.Empty<byte>(), OverlapEnds));
            Assert.Throws<FormatException>(() => WebhookSecret.FromUtf8(string.Empty));
            Assert.Throws<FormatException>(() => current.WithRotatingUtf8(string.Empty, OverlapEnds));
        }

        [Fact]
        public void TheRotatingSecretIsDecodedUnderItsEncoding()
        {
            WebhookSecret secret = WebhookSecret
                .Parse("whsec_AAAAAAAAAAAAAAAAAAAAAA==", SecretEncoding.StandardWebhooks)
                .WithRotating("whsec_3q2+7w==", SecretEncoding.StandardWebhooks, OverlapEnds);

            Assert.True(Matches(secret, Key));
        }

        [Fact]
        public void StandardWebhooksReferenceVectorVerifies()
        {
            WebhookSecret secret = WebhookSecret.Parse(
                "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw",
                SecretEncoding.StandardWebhooks);
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
            Assert.True(generated.Length <= StoredSecretMaxLength);
        }

        [Fact]
        public void GeneratedStandardWebhooksSecretsCarryThePrefix()
        {
            Assert.StartsWith(
                WebhookSecret.StandardWebhooksPrefix,
                SecretGenerator.Generate(SecretEncoding.StandardWebhooks),
                StringComparison.Ordinal);
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
            Assert.Throws<ArgumentOutOfRangeException>(
                () => SecretGenerator.Generate(SecretEncoding.Hex, SecretGenerator.MinByteLength - 1));
        }

        [Fact]
        public void GenerateRejectsAnUndefinedEncoding()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => SecretGenerator.Generate((SecretEncoding)99));
        }

        private static bool Matches(WebhookSecret secret, byte[] key) =>
            secret.Matches(
                HmacAlgorithm.Sha256,
                Message,
                HmacComputer.Compute(HmacAlgorithm.Sha256, key, Message),
                DateTimeOffset.UnixEpoch);
    }
}
