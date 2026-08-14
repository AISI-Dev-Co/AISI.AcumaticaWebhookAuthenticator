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
            // /26 splits inside a byte, so this fails if masking only handles whole octets.
            IpAllowlist allowlist = IpAllowlist.Parse("198.51.100.0/26");

            Assert.Equal(expected, allowlist.Contains(IPAddress.Parse(candidate)));
        }

        [Fact]
        public void HostBitsInAnEntry_AreMaskedToTheConventionalReading()
        {
            // 203.0.113.7/24 means 203.0.113.0/24, as every router config reads it.
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

        [Fact]
        public void Ipv4MappedIpv6Candidate_MatchesAnIpv4Entry()
        {
            // A dual-stack proxy reports an IPv4 caller as ::ffff:a.b.c.d; the allowlist must not
            // treat that as a different caller.
            IpAllowlist allowlist = IpAllowlist.Parse("203.0.113.0/24");

            Assert.True(allowlist.Contains(IPAddress.Parse("::ffff:203.0.113.9")));
        }

        [Fact]
        public void Ipv4MappedIpv6Entry_MatchesAnIpv4Candidate()
        {
            IpAllowlist allowlist = IpAllowlist.Parse("::ffff:203.0.113.9");

            Assert.True(allowlist.Contains(IPAddress.Parse("203.0.113.9")));
        }

        [Fact]
        public void FamiliesDoNotCrossMatch()
        {
            // 203.0.113.7 and a v6 address sharing leading bytes must not collide.
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

        [Fact]
        public void EmptyList_ThrowsRatherThanSilentlyDenyingEverything()
        {
            Assert.Throws<ArgumentException>(() => IpAllowlist.Parse());
        }

        [Theory]
        [InlineData("203.0.113.9")]
        [InlineData("203.0.113.0/24, 2001:db8::/32")]
        [InlineData(" 203.0.113.0/24 ,, 2001:db8::/32 ")]
        public void ParseCsv_AcceptsWhatTheScreenStores(string csv)
        {
            // The one tokenization both the maintenance screen and the request path use.
            Assert.True(IpAllowlist.ParseCsv(csv).Contains(IPAddress.Parse("203.0.113.9")));
        }

        [Fact]
        public void ParseCsv_WithOnlySeparators_ThrowsLikeAnEmptyList()
        {
            Assert.Throws<ArgumentException>(() => IpAllowlist.ParseCsv(","));
        }

        [Fact]
        public void ToString_ReportsTheEntriesAsWritten()
        {
            Assert.Equal("203.0.113.7, 2001:db8::/32", IpAllowlist.Parse("203.0.113.7", "2001:db8::/32").ToString());
        }
    }
}
