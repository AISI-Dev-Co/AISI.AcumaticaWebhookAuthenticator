// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System.Reflection;
using AISI.AcumaticaWebhookAuthenticator.Signing;
using Xunit;

namespace AISI.AcumaticaWebhookAuthenticator.Tests
{
    public class FixedTimeComparerTests
    {
        [Theory]
        [InlineData(new byte[] { 1, 2, 3 }, new byte[] { 1, 2, 3 }, true)]
        [InlineData(new byte[] { 1, 2, 3 }, new byte[] { 1, 2, 4 }, false)]
        [InlineData(new byte[] { 9, 2, 3 }, new byte[] { 1, 2, 3 }, false)]
        [InlineData(new byte[] { 1, 2 }, new byte[] { 1, 2, 3 }, false)]
        [InlineData(new byte[0], new byte[0], true)]
        [InlineData(null, new byte[] { 1 }, false)]
        [InlineData(new byte[] { 1 }, null, false)]
        [InlineData(null, null, false)]
        public void AreEqualOnlyForTwoIdenticalNonNullSequences(byte[]? left, byte[]? right, bool expected)
        {
            Assert.Equal(expected, FixedTimeComparer.AreEqual(left, right));
        }

        [Fact]
        public void ComparisonIsNotShortCircuitedByTheJit()
        {
            // Asserted structurally because timing assertions flake in CI and end up deleted.
            MethodInfo method = typeof(FixedTimeComparer).GetMethod(nameof(FixedTimeComparer.AreEqual))!;
            MethodImplAttributes flags = method.MethodImplementationFlags;

            Assert.True(flags.HasFlag(MethodImplAttributes.NoOptimization));
            Assert.True(flags.HasFlag(MethodImplAttributes.NoInlining));
        }
    }
}
