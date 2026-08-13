// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Text;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Diagnostics;
using AISI.AcumaticaWebhookAuthenticator.Signing;
using Xunit;

namespace AISI.AcumaticaWebhookAuthenticator.Tests
{
    public class TemplateTests
    {
        [Fact]
        public void BodyToken_ContributesRawBytesVerbatim()
        {
            // The whole library rests on this. A body that is not valid UTF-8 must reach the digest
            // unchanged; if the template ever routes the body through a string, these bytes come
            // back as U+FFFD and every signature over binary or mis-declared content silently
            // stops matching.
            byte[] body = { 0x7B, 0xFF, 0xFE, 0x00, 0x22, 0x7D };

            WebhookAuthContext request = RequestBuilder.Post().WithBodyBytes(body).Build();
            TemplateResolution resolution = SignedPayloadTemplate.Body.Resolve(request, null);

            Assert.True(resolution.Success);
            Assert.Equal(body, resolution.Bytes);
        }

        [Fact]
        public void BodyToken_PreservesABomRatherThanStrippingIt()
        {
            byte[] body = { 0xEF, 0xBB, 0xBF, 0x7B, 0x7D };

            WebhookAuthContext request = RequestBuilder.Post().WithBodyBytes(body).Build();
            TemplateResolution resolution = SignedPayloadTemplate.Body.Resolve(request, null);

            Assert.Equal(body, resolution.Bytes);
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
                .WithMethod("POST")
                .WithPath("/inbound")
                .Build();

            TemplateResolution resolution = SignedPayloadTemplate
                .Parse("{method}\n{path}\n{body}")
                .Resolve(request, null);

            Assert.True(resolution.Success);
            Assert.Equal("POST\n/inbound\nx", Encoding.UTF8.GetString(resolution.Bytes));
        }

        [Fact]
        public void HeaderToken_Resolves()
        {
            WebhookAuthContext request = RequestBuilder.Post()
                .WithBody("x")
                .WithHeader("X-Request-Id", "abc123")
                .Build();

            TemplateResolution resolution = SignedPayloadTemplate
                .Parse("{header:X-Request-Id}:{body}")
                .Resolve(request, null);

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
            // If the platform turns out not to surface the HTTP method, a template using {method}
            // should say so rather than report a signature mismatch.
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
        [InlineData("{nonsense}")]
        [InlineData("{body")]
        [InlineData("body}")]
        [InlineData("{header:}")]
        public void MalformedTemplate_ThrowsAtParseTime(string pattern)
        {
            // Parse time, not request time: a bad template is a developer error and should surface
            // when the handler is constructed rather than as an unexplained 401 in production.
            Assert.Throws<FormatException>(() => SignedPayloadTemplate.Parse(pattern));
        }
    }
}
