// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using AISI.AcumaticaWebhookAuthenticator.Diagnostics;
using AISI.AcumaticaWebhookAuthenticator.Signing;
using Xunit;

namespace AISI.AcumaticaWebhookAuthenticator.Tests
{
    public class IpAllowlistAuthenticatorTests
    {
        private static readonly IpAllowlist Allowlist = IpAllowlist.Parse("203.0.113.0/24");

        private static IpAllowlistAuthenticator Gate(
            IWebhookAuthenticator? inner = null,
            IpAllowlist? allowlist = null,
            string clientAddressHeader = IpAllowlistAuthenticator.DefaultClientAddressHeader,
            int trustedProxyDepth = IpAllowlistAuthenticator.DefaultTrustedProxyDepth) =>
            new(inner ?? new RecordingAuthenticator(AuthResult.Success()), allowlist ?? Allowlist, clientAddressHeader, trustedProxyDepth);

        private static WebhookAuthContext Forwarded(params string[] lines) =>
            RequestBuilder.Post().WithRepeatedHeader("X-Forwarded-For", lines).Build();

        [Fact]
        public void AllowedCaller_RunsTheInnerAuthenticator()
        {
            var inner = new RecordingAuthenticator(AuthResult.Success());

            Assert.True(Gate(inner).Authenticate(Forwarded("203.0.113.9")).Succeeded);
            Assert.Equal(1, inner.Calls);
        }

        [Fact]
        public void AllowedCaller_StillFailsWhenTheInnerAuthenticatorFails()
        {
            var inner = new RecordingAuthenticator(AuthResult.Fail(AuthFailureCode.SignatureMismatch));

            AuthResult result = Gate(inner).Authenticate(Forwarded("203.0.113.9"));

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.SignatureMismatch, result.FailureCode);
        }

        [Fact]
        public void DisallowedCaller_FailsWithoutRunningTheInnerAuthenticator()
        {
            var inner = new RecordingAuthenticator(AuthResult.Success());

            AuthResult result = Gate(inner).Authenticate(Forwarded("192.0.2.1"));

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.ClientAddressDenied, result.FailureCode);
            Assert.Equal(0, inner.Calls);
        }

        [Fact]
        public void MissingHeader_FailsClosed()
        {
            AuthResult result = Gate().Authenticate(RequestBuilder.Post().Build());

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.ClientAddressMissing, result.FailureCode);
        }

        [Fact]
        public void SpoofedLeftEntries_AreIgnored()
        {
            AuthResult result = Gate().Authenticate(Forwarded("203.0.113.9, 192.0.2.1"));

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.ClientAddressDenied, result.FailureCode);
        }

        [Fact]
        public void TrustedProxyDepthTwo_ReadsTheSecondEntryFromTheRight()
        {
            Assert.True(Gate(trustedProxyDepth: 2).Authenticate(Forwarded("203.0.113.9, 198.51.100.1")).Succeeded);
        }

        [Theory]
        [InlineData(2, "203.0.113.9")]
        [InlineData(3, "203.0.113.9", "198.51.100.1")]
        public void FewerEntriesThanTrustedDepth_FailsClosed(int trustedProxyDepth, params string[] lines)
        {
            AuthResult result = Gate(trustedProxyDepth: trustedProxyDepth).Authenticate(Forwarded(lines));

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.ClientAddressMalformed, result.FailureCode);
        }

        [Theory]
        [InlineData(1, "192.0.2.1", "192.0.2.2, 203.0.113.9")]
        [InlineData(2, "203.0.113.9", "198.51.100.1")]
        [InlineData(2, "192.0.2.1, 203.0.113.9", "198.51.100.1")]
        [InlineData(3, "192.0.2.1, 203.0.113.9, 198.51.100.1", "198.51.100.2")]
        public void RepeatedHeader_IsReadAsOneCommaJoinedLine(int trustedProxyDepth, params string[] lines)
        {
            Assert.True(Gate(trustedProxyDepth: trustedProxyDepth).Authenticate(Forwarded(lines)).Succeeded);
        }

        [Theory]
        [InlineData("203.0.113.9:4711")]
        [InlineData("[2001:db8::9]")]
        [InlineData("[2001:db8::9]:4711")]
        public void PortsAndBrackets_AreStripped(string entry)
        {
            IpAllowlistAuthenticator gate = Gate(allowlist: IpAllowlist.Parse("203.0.113.0/24", "2001:db8::/32"));

            Assert.True(gate.Authenticate(Forwarded(entry)).Succeeded);
        }

        [Theory]
        [InlineData("unknown")]
        [InlineData("")]
        [InlineData("203.0.113.9,")]
        [InlineData("[2001:db8::9")]
        [InlineData("[2001:db8::9]garbage")]
        [InlineData("[2001:db8::9]:")]
        [InlineData("[2001:db8::9]:12x")]
        [InlineData("203.0.113.9:")]
        [InlineData("203.0.113.9:12x")]
        public void UnparseableEntry_FailsAsMalformed(string entry)
        {
            AuthResult result = Gate().Authenticate(Forwarded(entry));

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.ClientAddressMalformed, result.FailureCode);
        }

        [Fact]
        public void CustomHeaderName_IsUsed()
        {
            WebhookAuthContext request = RequestBuilder.Post()
                .WithHeader("X-Real-IP", "203.0.113.9")
                .Build();

            Assert.True(Gate(clientAddressHeader: "X-Real-IP").Authenticate(request).Succeeded);
        }

        [Fact]
        public void Challenge_IsForwardedFromTheInnerScheme()
        {
            var basic = new BasicAuthenticator(new StaticSecretProvider(WebhookSecret.FromUtf8("a:b")), "gated");

            Assert.Equal(basic.Challenge, Gate(basic).Challenge);
            Assert.Null(Gate().Challenge);
        }

        [Fact]
        public void RequestPathDependency_IsForwardedFromTheInnerScheme()
        {
            var pathBound = new HmacAuthenticator(
                new HmacAuthOptions(new StaticSecretProvider(WebhookSecret.FromUtf8("k")), "X-Sig")
                {
                    Template = SignedPayloadTemplate.Parse("{path}{body}"),
                });

            Assert.True(Gate(pathBound).RequiresRequestPath);
            Assert.False(Gate().RequiresRequestPath);
        }

        [Fact]
        public void ZeroTrustedProxies_ThrowsAtConstruction()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => Gate(trustedProxyDepth: 0));
        }

        private sealed class RecordingAuthenticator : IWebhookAuthenticator
        {
            private readonly AuthResult _result;

            public RecordingAuthenticator(AuthResult result) => _result = result;

            public int Calls { get; private set; }

            public string Code => "STUB";

            public AuthResult Authenticate(WebhookAuthContext context)
            {
                Calls++;
                return _result;
            }
        }
    }
}
