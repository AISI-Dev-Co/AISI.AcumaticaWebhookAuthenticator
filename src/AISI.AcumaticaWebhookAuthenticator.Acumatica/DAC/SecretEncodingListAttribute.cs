// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using PX.Data;

namespace AISI.AcumaticaWebhookAuthenticator.Acumatica.DAC
{
    /// <summary>Stored codes for <see cref="SecretEncoding"/>.</summary>
    public sealed class SecretEncodingListAttribute : PXStringListAttribute
    {
        /// <summary><see cref="SecretEncoding.Utf8"/>.</summary>
        public const string Utf8 = "U";

        /// <summary><see cref="SecretEncoding.Base64"/>.</summary>
        public const string Base64 = "B";

        /// <summary><see cref="SecretEncoding.Hex"/>.</summary>
        public const string Hex = "H";

        /// <summary><see cref="SecretEncoding.StandardWebhooks"/>.</summary>
        public const string StandardWebhooks = "W";

        /// <summary>Creates the list.</summary>
        public SecretEncodingListAttribute()
            : base(
                new[] { Utf8, Base64, Hex, StandardWebhooks },
                new[] { Messages.EncodingUtf8, Messages.EncodingBase64, Messages.EncodingHex, Messages.EncodingStandardWebhooks })
        {
        }

        /// <summary>Maps a stored code to its encoding; blank is UTF-8.</summary>
        /// <exception cref="FormatException"><paramref name="code"/> is not a known code.</exception>
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
