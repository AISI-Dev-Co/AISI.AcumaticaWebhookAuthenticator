// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using AISI.AcumaticaWebhookAuthenticator.Diagnostics;
using Xunit;
using static AISI.AcumaticaWebhookAuthenticator.Tests.Vectors;

namespace AISI.AcumaticaWebhookAuthenticator.Tests
{
    public class SecretRotationTests
    {
        private const int OneDay = 86400;

        private static readonly DateTimeOffset Now = DateTimeOffset.UnixEpoch.AddDays(100);

        [Theory]
        [InlineData(GitHubSignature, OneDay, true)]
        [InlineData(GitHubRetiringSignature, OneDay, true)]
        [InlineData(GitHubSignature, -1, true)]
        [InlineData(GitHubRetiringSignature, -1, false)]
        public void TheRetiringSecretIsAcceptedOnlyUntilTheOverlapEnds(
            string signature,
            int overlapEndsInSeconds,
            bool expected)
        {
            WebhookSecret secret = WebhookSecret
                .FromUtf8(GitHubSecret)
                .WithRotatingUtf8(GitHubRetiringSecret, Now.AddSeconds(overlapEndsInSeconds));

            WebhookAuthContext request = RequestBuilder.Post()
                .WithBody(GitHubBody)
                .WithHeader("X-Hub-Signature-256", signature)
                .ReceivedAt(Now)
                .Build();

            AuthResult result = new HmacAuthenticator(WebhookAuthPresets.GitHub(new StaticSecretProvider(secret)))
                .Authenticate(request);

            Assert.Equal(expected, result.Succeeded);
            if (!expected)
            {
                Assert.Equal(AuthFailureCode.SignatureMismatch, result.FailureCode);
            }
        }
    }
}
