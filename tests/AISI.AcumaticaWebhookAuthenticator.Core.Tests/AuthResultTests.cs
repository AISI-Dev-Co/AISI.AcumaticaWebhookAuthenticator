// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Diagnostics;
using Xunit;

namespace AISI.AcumaticaWebhookAuthenticator.Tests
{
    public class AuthResultTests
    {
        [Theory]
        [InlineData("")]
        [InlineData(null)]
        public void BlankFailureCode_IsReportedAsUnspecified(string? failureCode)
        {
            AuthResult result = AuthResult.Fail(failureCode!);

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.Unspecified, result.FailureCode);
        }

        [Fact]
        public void DefaultResult_IsAnUnspecifiedFailure()
        {
            AuthResult result = default;

            Assert.False(result.Succeeded);
            Assert.Equal(AuthFailureCode.Unspecified, result.FailureCode);
        }
    }
}
