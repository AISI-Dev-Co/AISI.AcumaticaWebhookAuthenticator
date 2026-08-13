// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Diagnostics;
using AISI.AcumaticaWebhookAuthenticator.Signing;
using Xunit;

namespace AISI.AcumaticaWebhookAuthenticator.Tests
{
    /// <summary>
    /// The nullable annotations promise the context non-null header values, but the intended caller
    /// is a net48 adapter where the compiler enforces nothing. A null slipping through must degrade
    /// to an empty value and a 401, never surface as an exception — the library's own rule is that
    /// a hostile or odd request becomes a 401, not a 500.
    /// </summary>
    public class ContextHardeningTests
    {
        [Fact]
        public void ANullHeaderValueFromTheSingleValuedConstructorBecomesEmpty()
        {
            var headers = new Dictionary<string, string> { ["X-Odd"] = null! };

            WebhookAuthContext request = new WebhookAuthContext(
                Array.Empty<byte>(), headers, "POST", null, DateTimeOffset.UnixEpoch);

            Assert.True(request.TryGetHeader("X-Odd", out string value));
            Assert.Equal(string.Empty, value);
        }

        [Fact]
        public void ANullElementInAMultiValuedHeaderBecomesEmpty()
        {
            var headers = new Dictionary<string, IReadOnlyList<string>>
            {
                ["X-Odd"] = new[] { null!, "real" },
            };

            WebhookAuthContext request = new WebhookAuthContext(
                Array.Empty<byte>(), headers, "POST", null, DateTimeOffset.UnixEpoch);

            Assert.True(request.TryGetHeaderValues("X-Odd", out IReadOnlyList<string> values));
            Assert.Equal(string.Empty, values[0]);
            Assert.Equal("real", values[1]);
        }

        [Fact]
        public void ATemplateReferencingANullValuedHeaderResolvesRatherThanThrowing()
        {
            // The failure this pins: Encoding.UTF8.GetBytes(null) inside template resolution,
            // reached through TryGetHeader returning true with a null value.
            var headers = new Dictionary<string, string> { ["X-Request-Id"] = null! };

            WebhookAuthContext request = new WebhookAuthContext(
                new byte[] { 0x78 }, headers, "POST", null, DateTimeOffset.UnixEpoch);

            TemplateResolution resolution = SignedPayloadTemplate
                .Parse("{header:X-Request-Id}:{body}")
                .Resolve(request, null, capturePreview: true);

            Assert.True(resolution.Success);
            Assert.Equal(":x", resolution.Preview);
        }

        [Fact]
        public void ABodyOnlyTemplateAliasesTheBodyInsteadOfCopyingIt()
        {
            // The template's own doc refuses a per-request defensive copy of the body; the
            // resolution path must not quietly reintroduce one for the most common template.
            byte[] body = { 1, 2, 3, 4 };
            WebhookAuthContext request = RequestBuilder.Post().WithBodyBytes(body).Build();

            TemplateResolution resolution = SignedPayloadTemplate.Body.Resolve(request, null);

            Assert.Same(body, resolution.Bytes);
        }
    }
}
