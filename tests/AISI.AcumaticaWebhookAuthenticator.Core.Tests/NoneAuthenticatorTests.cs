// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using AISI.AcumaticaWebhookAuthenticator.Authentication;
using Xunit;

namespace AISI.AcumaticaWebhookAuthenticator.Tests
{
    public class NoneAuthenticatorTests
    {
        [Fact]
        public void AnyRequest_Authenticates()
        {
            Assert.True(NoneAuthenticator.Instance.Authenticate(RequestBuilder.Post().Build()).Succeeded);
        }
    }
}
