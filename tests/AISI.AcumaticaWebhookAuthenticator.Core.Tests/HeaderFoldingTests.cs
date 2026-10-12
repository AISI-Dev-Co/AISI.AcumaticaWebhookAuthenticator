// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System.Collections.Generic;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using AISI.AcumaticaWebhookAuthenticator.Diagnostics;
using Xunit;
using static AISI.AcumaticaWebhookAuthenticator.Tests.Vectors;

namespace AISI.AcumaticaWebhookAuthenticator.Tests
{
    /// <summary>A repeated signature header arrives either as distinct values or comma-folded into one.</summary>
    public class HeaderFoldingTests
    {
        [Theory]
        [InlineData(GitHubSignature + "," + GitHubDecoy)]
        [InlineData(GitHubDecoy + ", " + GitHubSignature)]
        [InlineData(GitHubDecoy + ",  " + GitHubSignature + " ,")]
        public void AFoldedHeaderCarryingTheValidSignatureAuthenticates(string headerValue)
        {
            Assert.True(Authenticate(headerValue).Succeeded);
        }

        [Theory]
        [InlineData(GitHubDecoy)]
        [InlineData(GitHubDecoy + "," + GitHubDecoy)]
        [InlineData("")]
        [InlineData(",,,")]
        public void AFoldedHeaderWithoutAValidSignatureIsRejected(string headerValue)
        {
            Assert.False(Authenticate(headerValue).Succeeded);
        }

        public static IEnumerable<object[]> RepeatedHeaders()
        {
            yield return new object[] { new[] { GitHubSignature, GitHubDecoy }, true };
            yield return new object[] { new[] { GitHubDecoy, GitHubSignature }, true };
            yield return new object[] { new[] { GitHubDecoy, GitHubSignature, GitHubDecoy }, true };
            yield return new object[] { new[] { GitHubDecoy, GitHubDecoy }, false };
        }

        [Theory]
        [MemberData(nameof(RepeatedHeaders))]
        public void ARepeatedHeaderIsExtractedFromEachValueIndependently(string[] headerValues, bool expected)
        {
            WebhookAuthContext request = RequestBuilder.Post()
                .WithBody(GitHubBody)
                .WithRepeatedHeader("X-Hub-Signature-256", headerValues)
                .Build();

            Assert.Equal(expected, Authenticator().Authenticate(request).Succeeded);
        }

        [Fact]
        public void TryGetHeaderFoldsARepeatedHeaderForTemplateUse()
        {
            string[] sent = { "a", "b" };
            WebhookAuthContext request = RequestBuilder.Post()
                .WithBody(GitHubBody)
                .WithRepeatedHeader("X-Trace", sent)
                .Build();

            Assert.True(request.TryGetHeader("X-Trace", out string folded));
            Assert.Equal("a,b", folded);

            Assert.True(request.TryGetHeaderValues("X-Trace", out IReadOnlyList<string> values));
            Assert.Equal(sent, values);
        }

        [Theory]
        [InlineData("sha256=zz,garbage")]
        [InlineData("garbage,sha256=zz")]
        public void TheDiagnosticCodeNamesTheMostSpecificFailureRegardlessOfOrder(string headerValue)
        {
            // 'sha256=zz' gets further (prefix ok, decode fails) than 'garbage' (prefix fails).
            AuthResult result = Authenticate(headerValue);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.SignatureMalformed, result.FailureCode);
        }

        private static HmacAuthenticator Authenticator() =>
            new HmacAuthenticator(WebhookAuthPresets.GitHub(
                new StaticSecretProvider(WebhookSecret.FromUtf8(GitHubSecret))));

        private static AuthResult Authenticate(string headerValue)
        {
            WebhookAuthContext request = RequestBuilder.Post()
                .WithBody(GitHubBody)
                .WithHeader("X-Hub-Signature-256", headerValue)
                .Build();

            return Authenticator().Authenticate(request);
        }
    }
}
