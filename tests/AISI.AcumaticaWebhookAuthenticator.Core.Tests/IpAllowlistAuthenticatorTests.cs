// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using AISI.AcumaticaWebhookAuthenticator.Diagnostics;
using Xunit;

namespace AISI.AcumaticaWebhookAuthenticator.Tests
{
    public class IpAllowlistAuthenticatorTests
    {
        private static readonly IpAllowlist Allowlist = IpAllowlist.Parse("203.0.113.0/24");

        [Fact]
        public void AllowedCaller_RunsTheInnerAuthenticator()
        {
            var inner = new RecordingAuthenticator(AuthResult.Success());
            var gate = new IpAllowlistAuthenticator(inner, Allowlist);

            WebhookAuthContext request = RequestBuilder.Post()
                .WithHeader("X-Forwarded-For", "203.0.113.9")
                .Build();

            Assert.True(gate.Authenticate(request).Succeeded);
            Assert.Equal(1, inner.Calls);
        }

        [Fact]
        public void AllowedCaller_StillFailsWhenTheInnerAuthenticatorFails()
        {
            // The gate is a restriction on top of authentication, never a substitute for it.
            var inner = new RecordingAuthenticator(AuthResult.Fail(AuthFailureCode.SignatureMismatch));
            var gate = new IpAllowlistAuthenticator(inner, Allowlist);

            WebhookAuthContext request = RequestBuilder.Post()
                .WithHeader("X-Forwarded-For", "203.0.113.9")
                .Build();

            AuthResult result = gate.Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.SignatureMismatch, result.FailureCode);
        }

        [Fact]
        public void DisallowedCaller_FailsWithoutRunningTheInnerAuthenticator()
        {
            var inner = new RecordingAuthenticator(AuthResult.Success());
            var gate = new IpAllowlistAuthenticator(inner, Allowlist);

            WebhookAuthContext request = RequestBuilder.Post()
                .WithHeader("X-Forwarded-For", "192.0.2.1")
                .Build();

            AuthResult result = gate.Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.ClientAddressDenied, result.FailureCode);
            Assert.Equal(0, inner.Calls);
        }

        [Fact]
        public void MissingHeader_FailsClosed()
        {
            var gate = new IpAllowlistAuthenticator(new RecordingAuthenticator(AuthResult.Success()), Allowlist);

            AuthResult result = gate.Authenticate(RequestBuilder.Post().Build());

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.ClientAddressMissing, result.FailureCode);
        }

        [Fact]
        public void SpoofedLeftEntries_AreIgnored()
        {
            // The attacker controls everything the trusted proxy did not append. With depth 1 only
            // the rightmost entry counts, so an allowed address planted on the left changes
            // nothing.
            var gate = new IpAllowlistAuthenticator(new RecordingAuthenticator(AuthResult.Success()), Allowlist);

            WebhookAuthContext request = RequestBuilder.Post()
                .WithHeader("X-Forwarded-For", "203.0.113.9, 192.0.2.1")
                .Build();

            AuthResult result = gate.Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.ClientAddressDenied, result.FailureCode);
        }

        [Fact]
        public void TrustedProxyDepthTwo_ReadsTheSecondEntryFromTheRight()
        {
            // CDN then load balancer: the rightmost entry is the CDN's own address, the one before
            // it is the caller as the CDN saw it.
            var gate = new IpAllowlistAuthenticator(
                new RecordingAuthenticator(AuthResult.Success()),
                Allowlist,
                trustedProxyDepth: 2);

            WebhookAuthContext request = RequestBuilder.Post()
                .WithHeader("X-Forwarded-For", "203.0.113.9, 198.51.100.1")
                .Build();

            Assert.True(gate.Authenticate(request).Succeeded);
        }

        [Fact]
        public void FewerEntriesThanTrustedDepth_FailsClosed()
        {
            // One entry under a depth-2 configuration means the request did not come through the
            // proxy chain the configuration describes; nothing in the header is evidence.
            var gate = new IpAllowlistAuthenticator(
                new RecordingAuthenticator(AuthResult.Success()),
                Allowlist,
                trustedProxyDepth: 2);

            WebhookAuthContext request = RequestBuilder.Post()
                .WithHeader("X-Forwarded-For", "203.0.113.9")
                .Build();

            AuthResult result = gate.Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.ClientAddressMalformed, result.FailureCode);
        }

        [Fact]
        public void RepeatedHeader_FlattensInArrivalOrder()
        {
            // Two header lines are equivalent to one comma-joined line, so with depth 1 the last
            // entry of the last line is the trusted one.
            var gate = new IpAllowlistAuthenticator(new RecordingAuthenticator(AuthResult.Success()), Allowlist);

            WebhookAuthContext request = RequestBuilder.Post()
                .WithRepeatedHeader("X-Forwarded-For", "192.0.2.1", "192.0.2.2, 203.0.113.9")
                .Build();

            Assert.True(gate.Authenticate(request).Succeeded);
        }

        [Theory]
        [InlineData("203.0.113.9:4711")]
        [InlineData("[2001:db8::9]")]
        [InlineData("[2001:db8::9]:4711")]
        public void PortsAndBrackets_AreStripped(string entry)
        {
            var gate = new IpAllowlistAuthenticator(
                new RecordingAuthenticator(AuthResult.Success()),
                IpAllowlist.Parse("203.0.113.0/24", "2001:db8::/32"));

            WebhookAuthContext request = RequestBuilder.Post()
                .WithHeader("X-Forwarded-For", entry)
                .Build();

            Assert.True(gate.Authenticate(request).Succeeded);
        }

        [Theory]
        [InlineData("unknown")]
        [InlineData("")]
        [InlineData("[2001:db8::9")]
        public void UnparseableEntry_FailsAsMalformed(string entry)
        {
            var gate = new IpAllowlistAuthenticator(new RecordingAuthenticator(AuthResult.Success()), Allowlist);

            WebhookAuthContext request = RequestBuilder.Post()
                .WithHeader("X-Forwarded-For", entry)
                .Build();

            AuthResult result = gate.Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.ClientAddressMalformed, result.FailureCode);
        }

        [Fact]
        public void CustomHeaderName_IsUsed()
        {
            var gate = new IpAllowlistAuthenticator(
                new RecordingAuthenticator(AuthResult.Success()),
                Allowlist,
                clientAddressHeader: "X-Real-IP");

            WebhookAuthContext request = RequestBuilder.Post()
                .WithHeader("X-Real-IP", "203.0.113.9")
                .Build();

            Assert.True(gate.Authenticate(request).Succeeded);
        }

        [Fact]
        public void Code_ReportsTheGateOnTopOfTheInnerScheme()
        {
            var gate = new IpAllowlistAuthenticator(new RecordingAuthenticator(AuthResult.Success()), Allowlist);

            Assert.Equal("STUB+IP", gate.Code);
        }

        [Fact]
        public void Challenge_IsForwardedFromTheInnerScheme()
        {
            // Wrapping a scheme must not silently drop its WWW-Authenticate challenge — the host
            // discovers it through IChallengeSource, which the gate forwards.
            var basic = new BasicAuthenticator(
                new StaticSecretProvider(WebhookSecret.FromUtf8("a:b")), "gated");
            var gate = new IpAllowlistAuthenticator(basic, Allowlist);

            Assert.Equal(basic.Challenge, ((IChallengeSource)gate).Challenge);
            Assert.Null(((IChallengeSource)new IpAllowlistAuthenticator(
                new RecordingAuthenticator(AuthResult.Success()), Allowlist)).Challenge);
        }

        [Fact]
        public void RequestPathDependency_IsForwardedFromTheInnerScheme()
        {
            // Wrapping must not hide a {path} dependency from a host that cannot supply one.
            var pathBound = new HmacAuthenticator(
                new Configuration.HmacAuthOptions(
                    new StaticSecretProvider(WebhookSecret.FromUtf8("k")), "X-Sig")
                {
                    Template = Signing.SignedPayloadTemplate.Parse("{path}{body}"),
                });
            var gate = new IpAllowlistAuthenticator(pathBound, Allowlist);

            Assert.True(((IRequestPathDependent)gate).RequiresRequestPath);
            Assert.False(((IRequestPathDependent)new IpAllowlistAuthenticator(
                new RecordingAuthenticator(AuthResult.Success()), Allowlist)).RequiresRequestPath);
        }

        [Fact]
        public void ZeroTrustedProxies_ThrowsAtConstruction()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new IpAllowlistAuthenticator(
                new RecordingAuthenticator(AuthResult.Success()),
                Allowlist,
                trustedProxyDepth: 0));
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
