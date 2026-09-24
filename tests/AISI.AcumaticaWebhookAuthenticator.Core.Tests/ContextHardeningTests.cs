// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Diagnostics;
using AISI.AcumaticaWebhookAuthenticator.Signing;
using Xunit;

namespace AISI.AcumaticaWebhookAuthenticator.Tests
{
    /// <summary>net48 callers get no nullable enforcement: null header values must degrade to empty, never throw.</summary>
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
            Assert.Equal(new[] { string.Empty, "real" }, values);
        }

        [Fact]
        public void ATemplateReferencingANullValuedHeaderResolvesRatherThanThrowing()
        {
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
            byte[] body = { 1, 2, 3, 4 };
            WebhookAuthContext request = RequestBuilder.Post().WithBodyBytes(body).Build();

            TemplateResolution resolution = SignedPayloadTemplate.Body.Resolve(request, null);

            Assert.Same(body, resolution.Bytes);
        }
    }
}
