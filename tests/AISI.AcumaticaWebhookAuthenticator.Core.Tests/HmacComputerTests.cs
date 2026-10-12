// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System.Text;
using AISI.AcumaticaWebhookAuthenticator.Signing;
using Xunit;
using static AISI.AcumaticaWebhookAuthenticator.Tests.Vectors;

namespace AISI.AcumaticaWebhookAuthenticator.Tests
{
    public class HmacComputerTests
    {
        [Theory]
        [InlineData(HmacAlgorithm.Sha1, "01dc10d0c83e72ed246219cdd91669667fe2ca59")]
        [InlineData(
            HmacAlgorithm.Sha512,
            "11ed355a617e98134e842012a7944ccf59c10256cb182357bd7e3a42013ff07c" +
            "376f8c14cf5cc1923da20b51d64256b2fb8ebbf100aa67a61326f61fea8111bc")]
        public void EachAlgorithmProducesItsKnownDigest(HmacAlgorithm algorithm, string expected)
        {
            byte[] digest = HmacComputer.Compute(
                algorithm,
                Encoding.UTF8.GetBytes(GitHubSecret),
                Encoding.UTF8.GetBytes(GitHubBody));

            Assert.Equal(expected, SignatureCodec.Encode(digest, SignatureEncoding.Hex));
        }
    }
}
