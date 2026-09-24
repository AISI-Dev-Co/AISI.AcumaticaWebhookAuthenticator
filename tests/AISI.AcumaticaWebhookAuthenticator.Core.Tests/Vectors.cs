// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System.Globalization;
using System.Text;
using AISI.AcumaticaWebhookAuthenticator.Signing;

namespace AISI.AcumaticaWebhookAuthenticator.Tests
{
    /// <summary>Known-good sender vectors shared across tests.</summary>
    internal static class Vectors
    {
        // From GitHub's webhook documentation, so an external anchor rather than our own output.
        public const string GitHubSecret = "It's a Secret to Everybody";
        public const string GitHubBody = "Hello, World!";
        public const string GitHubSignature =
            "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";

        public const string GitHubRetiringSecret = "old-secret";
        public const string GitHubRetiringSignature =
            "sha256=e7f4750c1d0580871565739b45147585cd7f2622003135f604ae5d6aac8f9577";

        public const string GitHubDecoy =
            "sha256=0000000000000000000000000000000000000000000000000000000000000000";

        public const string StripeSecret = "whsec_test_secret";
        public const string StripeBody = "{\"id\":\"evt_1\",\"object\":\"event\"}";
        public const long StripeTimestamp = 1614556800;
        public const string StripeV1 =
            "7a0685c65fcda9f1dd585b6eaa74ead6d954e5895ecc08263afbd424c5661b46";

        public const string StripeDecoy =
            "0000000000000000000000000000000000000000000000000000000000000000";

        /// <summary>Hex HMAC-SHA256 of <paramref name="message"/> under the UTF-8 <paramref name="secret"/>.</summary>
        public static string Sign(string secret, string message) =>
            SignatureCodec.Encode(
                HmacComputer.Compute(HmacAlgorithm.Sha256, Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes(message)),
                SignatureEncoding.Hex);

        /// <summary>A Stripe <c>v1</c> signature over <paramref name="timestamp"/>.<see cref="StripeBody"/>.</summary>
        public static string SignStripe(string timestamp) => Sign(StripeSecret, timestamp + "." + StripeBody);

        /// <summary>A Stripe <c>v1</c> signature over a Unix-seconds <paramref name="timestamp"/>.</summary>
        public static string SignStripe(long timestamp) => SignStripe(timestamp.ToString(CultureInfo.InvariantCulture));
    }
}
