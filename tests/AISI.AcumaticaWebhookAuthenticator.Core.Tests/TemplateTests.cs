// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Linq;
using System.Text;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Diagnostics;
using AISI.AcumaticaWebhookAuthenticator.Signing;
using Xunit;

namespace AISI.AcumaticaWebhookAuthenticator.Tests
{
    public class TemplateTests
    {
        [Theory]
        [InlineData(new byte[] { 0x7B, 0xFF, 0xFE, 0x00, 0x22, 0x7D })]
        [InlineData(new byte[] { 0xEF, 0xBB, 0xBF, 0x7B, 0x7D })]
        public void BodyBytesAreSignedVerbatim(byte[] body)
        {
            // Invalid UTF-8 and a BOM must survive: routing the body through a string would corrupt both.
            WebhookAuthContext request = RequestBuilder.Post().WithBodyBytes(body).Build();
            TemplateResolution resolution = SignedPayloadTemplate.TimestampDotBody.Resolve(request, "1");

            Assert.True(resolution.Success);
            Assert.Equal(Encoding.ASCII.GetBytes("1.").Concat(body), resolution.Bytes);
        }

        [Fact]
        public void TimestampDotBody_ComposesInOrder()
        {
            WebhookAuthContext request = RequestBuilder.Post().WithBody("{\"a\":1}").Build();
            TemplateResolution resolution = SignedPayloadTemplate.TimestampDotBody.Resolve(request, "1614556800");

            Assert.True(resolution.Success);
            Assert.Equal("1614556800.{\"a\":1}", Encoding.UTF8.GetString(resolution.Bytes));
        }

        [Fact]
        public void MethodAndPathTokens_Resolve()
        {
            WebhookAuthContext request = RequestBuilder.Post()
                .WithBody("x")
                .WithPath("/inbound")
                .Build();

            TemplateResolution resolution = SignedPayloadTemplate
                .Parse("{method}\n{path}\n{body}")
                .Resolve(request, null);

            Assert.True(resolution.Success);
            Assert.Equal("POST\n/inbound\nx", Encoding.UTF8.GetString(resolution.Bytes));
        }

        [Theory]
        [InlineData("{header:X-Request-Id}:{body}")]
        [InlineData("{ header:X-Request-Id }:{ body }")]
        public void HeaderToken_Resolves(string pattern)
        {
            WebhookAuthContext request = RequestBuilder.Post()
                .WithBody("x")
                .WithHeader("X-Request-Id", "abc123")
                .Build();

            TemplateResolution resolution = SignedPayloadTemplate.Parse(pattern).Resolve(request, null);

            Assert.True(resolution.Success);
            Assert.Equal("abc123:x", Encoding.UTF8.GetString(resolution.Bytes));
        }

        [Fact]
        public void HeaderToken_IsMatchedCaseInsensitively()
        {
            WebhookAuthContext request = RequestBuilder.Post()
                .WithBody("x")
                .WithHeader("x-request-id", "abc123")
                .Build();

            Assert.True(SignedPayloadTemplate.Parse("{header:X-Request-Id}").Resolve(request, null).Success);
        }

        [Fact]
        public void MissingHeader_FailsResolutionRatherThanSubstitutingEmpty()
        {
            WebhookAuthContext request = RequestBuilder.Post().WithBody("x").Build();

            TemplateResolution resolution = SignedPayloadTemplate
                .Parse("{header:X-Absent}:{body}")
                .Resolve(request, null);

            Assert.False(resolution.Success);
            Assert.Equal(AuthFailureCode.TemplateHeaderMissing, resolution.FailureCode);
        }

        [Fact]
        public void MissingTimestamp_FailsResolution()
        {
            WebhookAuthContext request = RequestBuilder.Post().WithBody("x").Build();
            TemplateResolution resolution = SignedPayloadTemplate.TimestampDotBody.Resolve(request, null);

            Assert.False(resolution.Success);
            Assert.Equal(AuthFailureCode.TimestampMissing, resolution.FailureCode);
        }

        [Fact]
        public void UnavailableMethod_FailsWithItsOwnCode()
        {
            WebhookAuthContext request = RequestBuilder.Post().WithBody("x").WithoutMethod().Build();
            TemplateResolution resolution = SignedPayloadTemplate.Parse("{method}{body}").Resolve(request, null);

            Assert.False(resolution.Success);
            Assert.Equal(AuthFailureCode.TemplateMethodUnavailable, resolution.FailureCode);
        }

        [Fact]
        public void UnavailablePath_FailsWithItsOwnCode()
        {
            WebhookAuthContext request = RequestBuilder.Post().WithBody("x").WithoutPath().Build();
            TemplateResolution resolution = SignedPayloadTemplate.Parse("{path}{body}").Resolve(request, null);

            Assert.False(resolution.Success);
            Assert.Equal(AuthFailureCode.TemplatePathUnavailable, resolution.FailureCode);
        }

        [Fact]
        public void EscapedBraces_AreLiterals()
        {
            WebhookAuthContext request = RequestBuilder.Post().WithBody("x").Build();
            TemplateResolution resolution = SignedPayloadTemplate.Parse("{{{body}}}").Resolve(request, null);

            Assert.True(resolution.Success);
            Assert.Equal("{x}", Encoding.UTF8.GetString(resolution.Bytes));
        }

        [Fact]
        public void EmptyTemplate_ResolvesToNothing()
        {
            WebhookAuthContext request = RequestBuilder.Post().WithBody("x").Build();
            TemplateResolution resolution = SignedPayloadTemplate.Parse(string.Empty).Resolve(request, null);

            Assert.True(resolution.Success);
            Assert.Empty(resolution.Bytes);
        }

        [Theory]
        [InlineData("{body}", false, false)]
        [InlineData("{timestamp}.{body}", true, false)]
        [InlineData("{path}{body}", false, true)]
        [InlineData("{method}\n{path}\n{timestamp}\n{body}", true, true)]
        [InlineData("", false, false)]
        public void ReferenceFlags_ReportEveryTokenNotJustTheFirst(string pattern, bool timestamp, bool path)
        {
            SignedPayloadTemplate template = SignedPayloadTemplate.Parse(pattern);

            Assert.Equal(timestamp, template.ReferencesTimestamp);
            Assert.Equal(path, template.ReferencesPath);
        }

        [Theory]
        [InlineData("{nonsense}")]
        [InlineData("{body")]
        [InlineData("body}")]
        [InlineData("{header:}")]
        [InlineData("{ header: }")]
        public void MalformedTemplate_ThrowsAtParseTime(string pattern)
        {
            Assert.Throws<FormatException>(() => SignedPayloadTemplate.Parse(pattern));
        }

        [Fact]
        public void ResolveDoesNotBuildThePreviewByDefault()
        {
            WebhookAuthContext request = RequestBuilder.Post().WithBody("a fairly large payload").Build();

            TemplateResolution resolution = SignedPayloadTemplate.Body.Resolve(request, null);

            Assert.True(resolution.Success);
            Assert.Equal(string.Empty, resolution.Preview);
        }

        [Fact]
        public void ResolveBuildsThePreviewWhenAsked()
        {
            WebhookAuthContext request = RequestBuilder.Post().WithBody("payload").Build();

            TemplateResolution resolution = SignedPayloadTemplate.Body.Resolve(request, null, capturePreview: true);

            Assert.Equal("payload", resolution.Preview);
        }

        [Fact]
        public void TheDigestIsUnaffectedByWhetherThePreviewWasCaptured()
        {
            SignedPayloadTemplate template = SignedPayloadTemplate.Parse("x{body}");
            WebhookAuthContext request = RequestBuilder.Post().WithBodyBytes(new byte[] { 0x7B, 0xFF, 0xFE, 0x7D }).Build();

            Assert.Equal(
                template.Resolve(request, null).Bytes,
                template.Resolve(request, null, capturePreview: true).Bytes);
        }
    }
}
