// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using PX.Data;

namespace AISI.AcumaticaWebhookAuthenticator.Acumatica.DAC
{
    /// <summary>The stored one-letter codes for each <see cref="SecretEncoding"/>.</summary>
    public sealed class SecretEncodingListAttribute : PXStringListAttribute
    {
        public const string Utf8 = "U";

        public const string Base64 = "B";

        public const string Hex = "H";

        public const string StandardWebhooks = "W";

        public SecretEncodingListAttribute()
            : base(
                new[] { Utf8, Base64, Hex, StandardWebhooks },
                new[] { Messages.EncodingUtf8, Messages.EncodingBase64, Messages.EncodingHex, Messages.EncodingStandardWebhooks })
        {
        }

        /// <summary>Maps a stored code to its encoding, treating blank as UTF-8 and throwing on an unknown code.</summary>
        public static SecretEncoding ToEncoding(string? code)
        {
            switch (code)
            {
                case null:
                case "":
                case Utf8:
                    return SecretEncoding.Utf8;
                case Base64:
                    return SecretEncoding.Base64;
                case Hex:
                    return SecretEncoding.Hex;
                case StandardWebhooks:
                    return SecretEncoding.StandardWebhooks;
                default:
                    throw new FormatException("'" + code + "' is not a known secret encoding.");
            }
        }
    }
}
