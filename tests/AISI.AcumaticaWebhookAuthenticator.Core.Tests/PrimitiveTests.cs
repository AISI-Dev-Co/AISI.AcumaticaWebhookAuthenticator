// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Reflection;
using AISI.AcumaticaWebhookAuthenticator.Signing;
using Xunit;

namespace AISI.AcumaticaWebhookAuthenticator.Tests
{
    public class FixedTimeComparerTests
    {
        [Fact]
        public void IdenticalArrays_AreEqual()
        {
            Assert.True(FixedTimeComparer.AreEqual(new byte[] { 1, 2, 3 }, new byte[] { 1, 2, 3 }));
        }

        [Fact]
        public void DifferenceInTheFinalByte_IsDetected()
        {
            Assert.False(FixedTimeComparer.AreEqual(new byte[] { 1, 2, 3 }, new byte[] { 1, 2, 4 }));
        }

        [Fact]
        public void DifferenceInTheFirstByte_IsDetected()
        {
            Assert.False(FixedTimeComparer.AreEqual(new byte[] { 9, 2, 3 }, new byte[] { 1, 2, 3 }));
        }

        [Fact]
        public void DifferentLengths_AreNotEqual()
        {
            Assert.False(FixedTimeComparer.AreEqual(new byte[] { 1, 2 }, new byte[] { 1, 2, 3 }));
        }

        [Fact]
        public void EmptyArrays_AreEqual()
        {
            Assert.True(FixedTimeComparer.AreEqual(Array.Empty<byte>(), Array.Empty<byte>()));
        }

        [Fact]
        public void NullOperands_AreNeverEqual()
        {
            Assert.False(FixedTimeComparer.AreEqual(null, new byte[] { 1 }));
            Assert.False(FixedTimeComparer.AreEqual(new byte[] { 1 }, null));
            Assert.False(FixedTimeComparer.AreEqual(null, null));
        }

        [Fact]
        public void ComparisonIsNotShortCircuitedByTheJit()
        {
            // Timing assertions flake in CI and end up deleted, so the guarantee is asserted
            // structurally instead: the method must keep the attributes that stop the JIT from
            // optimising the accumulator loop into an early exit.
            MethodInfo method = typeof(FixedTimeComparer).GetMethod(nameof(FixedTimeComparer.AreEqual))!;
            MethodImplAttributes flags = method.MethodImplementationFlags;

            Assert.True(flags.HasFlag(MethodImplAttributes.NoOptimization));
            Assert.True(flags.HasFlag(MethodImplAttributes.NoInlining));
        }
    }

    public class SignatureCodecTests
    {
        [Fact]
        public void Hex_RoundTrips()
        {
            byte[] digest = { 0x00, 0x0F, 0xA0, 0xFF };

            string encoded = SignatureCodec.Encode(digest, SignatureEncoding.Hex);

            Assert.Equal("000fa0ff", encoded);
            Assert.True(SignatureCodec.TryDecode(encoded, SignatureEncoding.Hex, out byte[] decoded));
            Assert.Equal(digest, decoded);
        }

        [Fact]
        public void Hex_AcceptsUppercase()
        {
            Assert.True(SignatureCodec.TryDecode("000FA0FF", SignatureEncoding.Hex, out byte[] decoded));
            Assert.Equal(new byte[] { 0x00, 0x0F, 0xA0, 0xFF }, decoded);
        }

        [Theory]
        [InlineData("abc")]
        [InlineData("zz")]
        [InlineData("")]
        [InlineData(null)]
        public void Hex_RejectsMalformedInput(string? value)
        {
            Assert.False(SignatureCodec.TryDecode(value, SignatureEncoding.Hex, out _));
        }

        [Fact]
        public void Base64_RoundTrips()
        {
            byte[] digest = { 0x01, 0x02, 0x03, 0x04, 0x05 };

            string encoded = SignatureCodec.Encode(digest, SignatureEncoding.Base64);

            Assert.True(SignatureCodec.TryDecode(encoded, SignatureEncoding.Base64, out byte[] decoded));
            Assert.Equal(digest, decoded);
        }

        [Fact]
        public void Base64_RejectsMalformedInputWithoutThrowing()
        {
            Assert.False(SignatureCodec.TryDecode("!!!not base64!!!", SignatureEncoding.Base64, out _));
        }
    }
}
