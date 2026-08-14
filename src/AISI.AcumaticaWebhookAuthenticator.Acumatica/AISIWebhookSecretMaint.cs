// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using AISI.AcumaticaWebhookAuthenticator.Acumatica.DAC;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using PX.Data;
using PX.Data.BQL.Fluent;

namespace AISI.AcumaticaWebhookAuthenticator.Acumatica
{
    /// <summary>
    /// Maintenance graph for webhook secrets — screen <c>AS301000</c>. Stored secrets are never
    /// displayed back; an administrator pastes a new value to replace one.
    /// </summary>
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
        /// Rejects a secret the storage cannot hold — a silently truncated credential verifies
        /// nothing and gives no hint why.
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
        /// Validates the allowlist with the same parser the request path uses — a typo caught here
        /// is a red field; at request time it denies every request until fixed.
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
        /// Requires the rotating-secret/expiry pair together — an overlap is supposed to close
        /// itself.
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
