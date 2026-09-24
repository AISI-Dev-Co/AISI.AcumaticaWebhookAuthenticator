// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Diagnostics;
using Xunit;

namespace AISI.AcumaticaWebhookAuthenticator.Tests
{
    public class AuthResultTests
    {
        [Fact]
        public void ADefaultAuthResultReportsAFailureRatherThanANullCode()
        {
            AuthResult result = default;

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.Unspecified, result.FailureCode);
        }

        [Fact]
        public void AnAbsentHeaderYieldsEmptyRatherThanNull()
        {
            WebhookAuthContext request = RequestBuilder.Post().WithBody("x").Build();

            Assert.False(request.TryGetHeader("X-Absent", out string value));
            Assert.Equal(string.Empty, value);
        }
    }
}
