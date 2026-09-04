// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using PX.Common;

namespace AISI.AcumaticaWebhookAuthenticator.Acumatica
{
    /// <summary>Localizable screen messages.</summary>
    [PXLocalizable]
    public static class Messages
    {
        /// <summary>Field-verifying rejection for an over-long secret: label, limit, actual length.</summary>
        public const string SecretTooLong =
            "{0} cannot exceed {1} characters; it is {2}. It was not saved - a truncated secret would never verify.";

        /// <summary>The allowlist failed to parse; {0} carries the parser's reason.</summary>
        public const string AllowlistInvalid = "The IP allowlist is not valid: {0}";

        /// <summary>The allowlist contains separators but no entries.</summary>
        public const string AllowlistEmpty =
            "The allowlist contains no entries. Leave the field blank for no IP restriction.";

        /// <summary>A rotating secret was entered without an end date.</summary>
        public const string RotatingSecretNeedsExpiry =
            "A rotating secret requires an end date; without one the retired secret would be accepted forever.";

        /// <summary>A rotation end date was entered without a rotating secret.</summary>
        public const string RotationExpiryNeedsSecret =
            "A rotation end date is set but there is no rotating secret to expire.";
    }
}
