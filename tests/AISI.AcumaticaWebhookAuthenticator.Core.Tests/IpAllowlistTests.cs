// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Net;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using Xunit;

namespace AISI.AcumaticaWebhookAuthenticator.Tests
{
    public class IpAllowlistTests
    {
        [Fact]
        public void BareAddress_MatchesExactlyThatAddress()
        {
            IpAllowlist allowlist = IpAllowlist.Parse("203.0.113.7");

            Assert.True(allowlist.Contains(IPAddress.Parse("203.0.113.7")));
            Assert.False(allowlist.Contains(IPAddress.Parse("203.0.113.8")));
        }

        [Theory]
        [InlineData("203.0.113.0", true)]
        [InlineData("203.0.113.255", true)]
        [InlineData("203.0.114.0", false)]
        [InlineData("203.0.112.255", false)]
        public void CidrBlock_MatchesItsRangeExactly(string candidate, bool expected)
        {
            IpAllowlist allowlist = IpAllowlist.Parse("203.0.113.0/24");

            Assert.Equal(expected, allowlist.Contains(IPAddress.Parse(candidate)));
        }

        [Theory]
        [InlineData("198.51.100.63", true)]   // top of /26
        [InlineData("198.51.100.64", false)]  // first past it
        public void NonOctetPrefix_MasksMidByte(string candidate, bool expected)
        {
            IpAllowlist allowlist = IpAllowlist.Parse("198.51.100.0/26");

            Assert.Equal(expected, allowlist.Contains(IPAddress.Parse(candidate)));
        }

        [Fact]
        public void HostBitsInAnEntry_AreMaskedToTheConventionalReading()
        {
            IpAllowlist allowlist = IpAllowlist.Parse("203.0.113.7/24");

            Assert.True(allowlist.Contains(IPAddress.Parse("203.0.113.200")));
        }

        [Theory]
        [InlineData("2001:db8::1", true)]
        [InlineData("2001:db8:0:0:0:0:0:1", true)]  // same address, long spelling
        [InlineData("2001:db8::2", false)]
        public void Ipv6Address_MatchesRegardlessOfSpelling(string candidate, bool expected)
        {
            IpAllowlist allowlist = IpAllowlist.Parse("2001:db8::1");

            Assert.Equal(expected, allowlist.Contains(IPAddress.Parse(candidate)));
        }

        [Theory]
        [InlineData("2001:db8:ffff::1", true)]
        [InlineData("2001:db9::1", false)]
        public void Ipv6CidrBlock_Matches(string candidate, bool expected)
        {
            IpAllowlist allowlist = IpAllowlist.Parse("2001:db8::/32");

            Assert.Equal(expected, allowlist.Contains(IPAddress.Parse(candidate)));
        }

        [Theory]
        [InlineData("203.0.113.0/24", "::ffff:203.0.113.9")]
        [InlineData("::ffff:203.0.113.9", "203.0.113.9")]
        public void Ipv4MappedIpv6_MatchesTheCorrespondingIpv4(string entry, string candidate)
        {
            // Dual-stack proxies report IPv4 callers as ::ffff:a.b.c.d.
            Assert.True(IpAllowlist.Parse(entry).Contains(IPAddress.Parse(candidate)));
        }

        [Fact]
        public void FamiliesDoNotCrossMatch()
        {
            // 0.0.0.0/0 covers every IPv4 address and no IPv6 one.
            IpAllowlist allowlist = IpAllowlist.Parse("0.0.0.0/0");

            Assert.True(allowlist.Contains(IPAddress.Parse("203.0.113.7")));
            Assert.False(allowlist.Contains(IPAddress.Parse("2001:db8::1")));
        }

        [Fact]
        public void MultipleEntries_AnyMatchAllows()
        {
            IpAllowlist allowlist = IpAllowlist.Parse("203.0.113.7", "198.51.100.0/24", "2001:db8::/32");

            Assert.True(allowlist.Contains(IPAddress.Parse("198.51.100.42")));
            Assert.True(allowlist.Contains(IPAddress.Parse("2001:db8::9")));
            Assert.False(allowlist.Contains(IPAddress.Parse("192.0.2.1")));
        }

        [Fact]
        public void NullCandidate_IsNeverContained()
        {
            Assert.False(IpAllowlist.Parse("0.0.0.0/0").Contains(null));
        }

        [Theory]
        [InlineData("not-an-address")]
        [InlineData("203.0.113.0/33")]
        [InlineData("2001:db8::/129")]
        [InlineData("203.0.113.0/-1")]
        [InlineData("203.0.113.0/abc")]
        [InlineData("203.0.113.0/")]
        [InlineData("")]
        [InlineData(" ")]
        public void MalformedEntry_ThrowsAtParseTime(string entry)
        {
            Assert.Throws<FormatException>(() => IpAllowlist.Parse(entry));
        }

        [Theory]
        [InlineData("10")]
        [InlineData("10/8")]
        [InlineData("10.1")]
        [InlineData("10.0.1")]
        [InlineData("167772161")]
        [InlineData("010.0.0.1")]
        [InlineData("0x0A.0.0.1")]
        [InlineData("10.0.0.256")]
        [InlineData("10.0.0.1.5")]
        [InlineData("10..0.1")]
        [InlineData("+10.0.0.1")]
        public void Ipv4MustBeFourDottedDecimalOctets(string entry)
        {
            // IPAddress.TryParse would read "10/8" as 0.0.0.10/8, i.e. 0.0.0.0/8.
            Assert.Throws<FormatException>(() => IpAllowlist.Parse(entry));
        }

        [Fact]
        public void EmptyList_ThrowsRatherThanSilentlyDenyingEverything()
        {
            Assert.Throws<ArgumentException>(() => IpAllowlist.Parse());
        }

        [Theory]
        [InlineData("203.0.113.9")]
        [InlineData("203.0.113.0/24, 2001:db8::/32")]
        [InlineData(" 203.0.113.0/24 ,, 2001:db8::/32 ")]
        [InlineData("203.0.113.0/24,  ,2001:db8::/32")]
        public void ParseCsv_AcceptsWhatTheScreenStores(string csv)
        {
            Assert.True(IpAllowlist.ParseCsv(csv).Contains(IPAddress.Parse("203.0.113.9")));
        }

        [Theory]
        [InlineData("")]
        [InlineData(",")]
        [InlineData("  ,  ")]
        public void ParseCsv_WithNoEntries_ThrowsLikeAnEmptyList(string csv)
        {
            Assert.Throws<ArgumentException>(() => IpAllowlist.ParseCsv(csv));
        }
    }
}
