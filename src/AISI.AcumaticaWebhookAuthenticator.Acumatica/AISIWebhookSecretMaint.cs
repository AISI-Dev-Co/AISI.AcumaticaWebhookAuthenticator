// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using AISI.AcumaticaWebhookAuthenticator.Acumatica.DAC;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using PX.Data;
using PX.Data.BQL.Fluent;

namespace AISI.AcumaticaWebhookAuthenticator.Acumatica
{
    /// <summary>
    /// Maintenance graph for webhook secrets — screen <c>AS301000</c>. One grid: webhook, secret,
    /// and the optional rotation pair.
    /// </summary>
    /// <remarks>
    /// The screen never displays a stored secret back; <c>[PXRSACryptString]</c> masks it in the
    /// UI. An administrator pastes a new value to replace one, which is the correct workflow for
    /// credential fields.
    /// </remarks>
    public class AISIWebhookSecretMaint : PXGraph<AISIWebhookSecretMaint>
    {
        // The framework populates action and view members by reflection during graph
        // construction; the null-forgiving initialisers acknowledge that, they do not perform it.

        /// <summary>Standard Cancel.</summary>
        public PXCancel<AISIWebhookSecret> Cancel = null!;

        /// <summary>Standard Save.</summary>
        public PXSave<AISIWebhookSecret> Save = null!;

        /// <summary>All webhook secrets.</summary>
        public SelectFrom<AISIWebhookSecret>.View Secrets = null!;

        /// <summary>
        /// Rejects a secret the storage cannot hold. The DAC field is 255 characters and
        /// <c>[PXRSACryptString]</c> would otherwise persist a silently truncated credential —
        /// which verifies nothing, fails every request, and gives no hint why.
        /// </summary>
        protected virtual void _(Events.FieldVerifying<AISIWebhookSecret, AISIWebhookSecret.secret> e)
        {
            RejectOverlongSecret(e.Row, e.NewValue, "Secret");
        }

        /// <summary>Same limit for the rotating secret.</summary>
        protected virtual void _(Events.FieldVerifying<AISIWebhookSecret, AISIWebhookSecret.rotatingSecret> e)
        {
            RejectOverlongSecret(e.Row, e.NewValue, "Rotating Secret");
        }

        /// <summary>
        /// Validates the allowlist with the same parser the request path uses, so what the screen
        /// accepts is exactly what will run. A typo caught here is a red field; the same typo in
        /// the database at request time denies every request until fixed.
        /// </summary>
        protected virtual void _(Events.FieldVerifying<AISIWebhookSecret, AISIWebhookSecret.allowedAddresses> e)
        {
            if (!(e.NewValue is string text) || string.IsNullOrWhiteSpace(text))
            {
                return;
            }

            try
            {
                IpAllowlist.ParseCsv(text);
            }
            catch (FormatException failure)
            {
                throw new PXSetPropertyException(e.Row, Messages.AllowlistInvalid, failure.Message);
            }
            catch (ArgumentException)
            {
                // Only separators, no entries: nothing would be allowed. Blank the field instead
                // if no restriction is wanted.
                throw new PXSetPropertyException(e.Row, Messages.AllowlistEmpty);
            }
        }

        /// <summary>
        /// A rotating secret without an expiry would be accepted forever — rotation overlap is
        /// supposed to close itself. Require the pair together.
        /// </summary>
        protected virtual void _(Events.RowPersisting<AISIWebhookSecret> e)
        {
            if (e.Row is null)
            {
                return;
            }

            bool hasRotating = !string.IsNullOrEmpty(e.Row.RotatingSecret);
            bool hasExpiry = e.Row.RotatingExpiresOn is object;

            if (hasRotating && !hasExpiry)
            {
                e.Cache.RaiseExceptionHandling<AISIWebhookSecret.rotatingExpiresOn>(
                    e.Row,
                    null,
                    new PXSetPropertyException(e.Row, Messages.RotatingSecretNeedsExpiry));
            }

            if (hasExpiry && !hasRotating)
            {
                e.Cache.RaiseExceptionHandling<AISIWebhookSecret.rotatingSecret>(
                    e.Row,
                    null,
                    new PXSetPropertyException(e.Row, Messages.RotationExpiryNeedsSecret));
            }
        }

        private static void RejectOverlongSecret(AISIWebhookSecret? row, object? newValue, string fieldLabel)
        {
            if (newValue is string text && text.Length > AISIWebhookSecret.SecretLength)
            {
                throw new PXSetPropertyException(
                    row,
                    Messages.SecretTooLong,
                    fieldLabel,
                    AISIWebhookSecret.SecretLength,
                    text.Length);
            }
        }
    }
}
