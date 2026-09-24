// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using Xunit;

namespace AISI.AcumaticaWebhookAuthenticator.Tests
{
    public class SignatureExtractionTests
    {
        [Theory]
        [InlineData("D0UMXmhjwBRi4y66TmhJrDlhQABD7zI2fm3p6/QLMo8=", "D0UMXmhjwBRi4y66TmhJrDlhQABD7zI2fm3p6/QLMo8=")]
        [InlineData("  abc  ", "abc")]
        public void WholeValueExtractionYieldsOneTrimmedSignature(string headerValue, string expected)
        {
            Assert.Equal(expected, Assert.Single(SignatureExtraction.Whole.Extract(headerValue)));
        }

        [Fact]
        public void KeyValueExtractionYieldsEveryMatchingElementInOrder()
        {
            SignatureExtraction extraction = SignatureExtraction.KeyValueElement("v1");
            string[] expected = { "a", "b" };

            Assert.Equal(expected, extraction.Extract("t=1, v1=a ,v0=x,V1=b"));
        }

        [Fact]
        public void EqualSeparatorsAreRejected()
        {
            Assert.Throws<ArgumentException>(
                () => SignatureExtraction.KeyValueElement("v1", pairSeparator: '=', keyValueSeparator: '='));

            Assert.Throws<ArgumentException>(
                () => TimestampValidation.FromSignatureHeaderElement(
                    "t",
                    TimeSpan.FromMinutes(5),
                    pairSeparator: ';',
                    keyValueSeparator: ';'));
        }
    }
}
