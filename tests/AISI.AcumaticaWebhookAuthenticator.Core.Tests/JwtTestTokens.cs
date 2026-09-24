// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Text;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Signing;

namespace AISI.AcumaticaWebhookAuthenticator.Tests
{
    /// <summary>Mints compact JWS tokens for tests.</summary>
    internal static class JwtTestTokens
    {
        internal static string Base64Url(byte[] data) =>
            Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        internal static string Base64Url(string text) => Base64Url(Encoding.UTF8.GetBytes(text));

        internal static string BodyHash(byte[] body) => Base64Url(JwtAuthenticator.ComputeBodyHash(body));

        internal static string Compact(HmacAlgorithm algorithm, byte[] key, string payloadJson)
        {
            string alg = algorithm == HmacAlgorithm.Sha512 ? "HS512" : "HS256";
            return Sign("{\"alg\":\"" + alg + "\",\"typ\":\"JWT\"}", payloadJson, key, algorithm);
        }

        internal static string Sign(
            string headerJson,
            string payloadJson,
            byte[] key,
            HmacAlgorithm algorithm = HmacAlgorithm.Sha256) =>
            SignSegments(Base64Url(headerJson), Base64Url(payloadJson), key, algorithm);

        internal static string SignSegments(
            string headerSegment,
            string payloadSegment,
            byte[] key,
            HmacAlgorithm algorithm = HmacAlgorithm.Sha256)
        {
            string signingInput = headerSegment + "." + payloadSegment;
            byte[] signature = HmacComputer.Compute(algorithm, key, Encoding.ASCII.GetBytes(signingInput));
            return signingInput + "." + Base64Url(signature);
        }
    }
}
