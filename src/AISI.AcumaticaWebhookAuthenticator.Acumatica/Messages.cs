// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using PX.Common;

namespace AISI.AcumaticaWebhookAuthenticator.Acumatica
{
    [PXLocalizable]
    public static class Messages
    {
        #region Secret validation
        public const string SecretTooLong =
            "{0} cannot exceed {1} characters; it is {2}. It was not saved - a truncated secret would never verify.";

        public const string SecretNotDecodable = "{0} does not match the selected secret encoding. {1}";
        #endregion

        #region Allowlist validation
        public const string AllowlistInvalid = "The IP allowlist is not valid: {0}";

        public const string AllowlistEmpty =
            "The allowlist contains no entries. Leave the field blank for no IP restriction.";
        #endregion

        #region Rotation
        public const string RotatingSecretNeedsExpiry =
            "A rotating secret requires an end date; without one the retired secret would be accepted forever.";

        public const string RotationExpiryNeedsSecret =
            "A rotation end date is set but there is no rotating secret to expire.";

        public const string SelectWebhookFirst = "Select a webhook first.";

        public const string SaveBeforeRotating = "Save or cancel your changes before rotating the secret.";

        public const string NothingToRotate = "There is no saved secret to rotate. Use Generate Secret instead.";

        public const string RotationInProgress =
            "A rotation is already in progress until {0:u}. Wait for it to end, or clear the rotating secret, before rotating again.";
        #endregion

        #region Secret encoding labels
        public const string EncodingUtf8 = "Text (UTF-8)";

        public const string EncodingBase64 = "Base64";

        public const string EncodingHex = "Hex";

        public const string EncodingStandardWebhooks = "Standard Webhooks (whsec_)";
        #endregion
    }
}
