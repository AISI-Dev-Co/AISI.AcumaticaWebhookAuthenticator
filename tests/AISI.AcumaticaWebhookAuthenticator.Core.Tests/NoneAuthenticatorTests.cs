// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
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

        [Fact]
        public void NullContext_StillThrows()
        {
            // Allow-all applies to requests, not to programming errors.
            Assert.Throws<ArgumentNullException>(() => NoneAuthenticator.Instance.Authenticate(null!));
        }

        [Fact]
        public void Code_ReportsNone()
        {
            Assert.Equal("NONE", NoneAuthenticator.Instance.Code);
        }
    }
}
