// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using AISI.AcumaticaWebhookAuthenticator.Diagnostics;
using Xunit;
using static AISI.AcumaticaWebhookAuthenticator.Tests.Vectors;

namespace AISI.AcumaticaWebhookAuthenticator.Tests
{
    public class HmacAuthenticatorTests
    {
        [Fact]
        public void NoSecretConfigured_DeniesRatherThanAllowing()
        {
            WebhookAuthContext request = RequestBuilder.Post()
                .WithBody(GitHubBody)
                .WithHeader("X-Hub-Signature-256", "sha256=00")
                .Build();

            AuthResult result = new HmacAuthenticator(WebhookAuthPresets.GitHub(new NullSecretProvider()))
                .Authenticate(request);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.SecretUnavailable, result.FailureCode);
        }

        [Fact]
        public void ARepeatedStripeHeaderVerifiesEachValueAgainstItsOwnTimestamp()
        {
            const long stale = StripeTimestamp - 800;

            AuthResult result = AuthenticateStripe(
                $"t={stale},v1={StripeDecoy}",
                $"t={StripeTimestamp},v1={SignStripe(StripeTimestamp)}");

            Assert.True(result.Succeeded);
        }

        [Fact]
        public void TheReplayWindowIsJudgedOnTheMatchingValuesTimestamp()
        {
            const long stale = StripeTimestamp - 3600;

            AuthResult result = AuthenticateStripe(
                $"t={StripeTimestamp},v1={StripeDecoy}",
                $"t={stale},v1={SignStripe(stale)}");

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.TimestampOutsideTolerance, result.FailureCode);
        }

        private static AuthResult AuthenticateStripe(params string[] headerValues)
        {
            WebhookAuthContext request = RequestBuilder.Post()
                .WithBody(StripeBody)
                .WithRepeatedHeader("Stripe-Signature", headerValues)
                .ReceivedAtUnixSeconds(StripeTimestamp)
                .Build();

            return new HmacAuthenticator(
                    WebhookAuthPresets.Stripe(new StaticSecretProvider(WebhookSecret.FromUtf8(StripeSecret))))
                .Authenticate(request);
        }
    }
}
