// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using AISI.AcumaticaWebhookAuthenticator.Signing;
using Xunit;

namespace AISI.AcumaticaWebhookAuthenticator.Tests
{
    public class SignatureCodecTests
    {
        [Theory]
        [InlineData(new byte[] { 0x00, 0x0F, 0xA0, 0xFF }, SignatureEncoding.Hex, "000fa0ff")]
        [InlineData(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 }, SignatureEncoding.Base64, "AQIDBAU=")]
        public void EncodingRoundTrips(byte[] digest, SignatureEncoding encoding, string expected)
        {
            string encoded = SignatureCodec.Encode(digest, encoding);

            Assert.Equal(expected, encoded);
            Assert.True(SignatureCodec.TryDecode(encoded, encoding, out byte[] decoded));
            Assert.Equal(digest, decoded);
        }

        [Fact]
        public void HexDecodingAcceptsUppercase()
        {
            Assert.True(SignatureCodec.TryDecode("000FA0FF", SignatureEncoding.Hex, out byte[] decoded));
            Assert.Equal(new byte[] { 0x00, 0x0F, 0xA0, 0xFF }, decoded);
        }

        [Theory]
        [InlineData("abc", SignatureEncoding.Hex)]
        [InlineData("zz", SignatureEncoding.Hex)]
        [InlineData("", SignatureEncoding.Hex)]
        [InlineData(null, SignatureEncoding.Hex)]
        [InlineData("!!!not base64!!!", SignatureEncoding.Base64)]
        [InlineData("", SignatureEncoding.Base64)]
        [InlineData("00", (SignatureEncoding)99)]
        public void MalformedInputIsRejectedWithoutThrowing(string? value, SignatureEncoding encoding)
        {
            Assert.False(SignatureCodec.TryDecode(value, encoding, out byte[] decoded));
            Assert.Empty(decoded);
        }
    }
}
