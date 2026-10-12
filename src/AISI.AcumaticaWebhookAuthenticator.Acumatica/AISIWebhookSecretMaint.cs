// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections;
using System.Linq;
using AISI.AcumaticaWebhookAuthenticator.Acumatica.DAC;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using PX.Data;
using PX.Data.BQL.Fluent;

namespace AISI.AcumaticaWebhookAuthenticator.Acumatica
{
    /// <summary>
    /// Webhook secrets screen (AS301000). Stored values are write-only; a generated secret is
    /// shown once, in a dialog.
    /// </summary>
    public class AISIWebhookSecretMaint : PXGraph<AISIWebhookSecretMaint, AISIWebhookSecret>
    {
        /// <summary>How long Rotate Secret keeps the retired secret accepted, in days.</summary>
        public const int RotationOverlapDays = 7;

        #region Views and actions
        /// <summary>All webhook secrets.</summary>
        public SelectFrom<AISIWebhookSecret>.View Secrets = null!;

        /// <summary>The generated-secret dialog.</summary>
        public PXFilter<AISIWebhookSecretReveal> Reveal = null!;

        /// <summary>Replaces the secret with a random one, immediately.</summary>
        public PXAction<AISIWebhookSecret> GenerateSecret = null!;

        /// <summary>Replaces the secret with a random one, keeping the old one live for <see cref="RotationOverlapDays"/>.</summary>
        public PXAction<AISIWebhookSecret> RotateSecret = null!;

        /// <summary>Handler for <see cref="GenerateSecret"/>.</summary>
        [PXButton(CommitChanges = true)]
        [PXUIField(DisplayName = "Generate Secret", MapEnableRights = PXCacheRights.Update, MapViewRights = PXCacheRights.Update)]
        protected virtual IEnumerable generateSecret(PXAdapter adapter)
        {
            if (Reveal.View.Answer == WebDialogResult.None)
            {
                StoreNewSecret(RequireCurrent(), rotate: false);
            }

            return RevealOnce(adapter);
        }

        /// <summary>Handler for <see cref="RotateSecret"/>.</summary>
        [PXButton(CommitChanges = true)]
        [PXUIField(DisplayName = "Rotate Secret", MapEnableRights = PXCacheRights.Update, MapViewRights = PXCacheRights.Update)]
        protected virtual IEnumerable rotateSecret(PXAdapter adapter)
        {
            if (Reveal.View.Answer == WebDialogResult.None)
            {
                StoreNewSecret(RequireCurrent(), rotate: true);
            }

            return RevealOnce(adapter);
        }
        #endregion

        #region Persistence
        /// <inheritdoc/>
        public override void Persist()
        {
            foreach (AISIWebhookSecret row in Secrets.Cache.Inserted.Cast<AISIWebhookSecret>()
                .Concat(Secrets.Cache.Updated.Cast<AISIWebhookSecret>()))
            {
                EnsureDecodable(row);
            }

            base.Persist();
        }
        #endregion

        #region Event handlers
        /// <summary>
        /// Rejects a secret the storage cannot hold — a silently truncated credential verifies
        /// nothing and gives no hint why.
        /// </summary>
        protected virtual void _(Events.FieldVerifying<AISIWebhookSecret, AISIWebhookSecret.secret> e)
        {
            RejectOverlongSecret<AISIWebhookSecret.secret>(e.Cache, e.Row, e.NewValue);
        }

        /// <summary>Same limit for the rotating secret.</summary>
        protected virtual void _(Events.FieldVerifying<AISIWebhookSecret, AISIWebhookSecret.rotatingSecret> e)
        {
            RejectOverlongSecret<AISIWebhookSecret.rotatingSecret>(e.Cache, e.Row, e.NewValue);
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
            if (e.Row is null || e.Operation == PXDBOperation.Delete)
            {
                return;
            }

            bool hasRotating = !string.IsNullOrEmpty(e.Row.RotatingSecret);
            bool hasExpiry = e.Row.RotatingExpiresOn is object;

            // RaiseExceptionHandling marks the field red; the throw is what actually blocks the
            // save - without it the row commits with the error displayed.
            if (hasRotating && !hasExpiry)
            {
                e.Cache.RaiseExceptionHandling<AISIWebhookSecret.rotatingExpiresOn>(
                    e.Row,
                    null,
                    new PXSetPropertyException(e.Row, Messages.RotatingSecretNeedsExpiry));

                throw new PXRowPersistingException(
                    nameof(AISIWebhookSecret.rotatingExpiresOn),
                    null,
                    Messages.RotatingSecretNeedsExpiry);
            }

            if (hasExpiry && !hasRotating)
            {
                e.Cache.RaiseExceptionHandling<AISIWebhookSecret.rotatingSecret>(
                    e.Row,
                    null,
                    new PXSetPropertyException(e.Row, Messages.RotationExpiryNeedsSecret));

                throw new PXRowPersistingException(
                    nameof(AISIWebhookSecret.rotatingSecret),
                    null,
                    Messages.RotationExpiryNeedsSecret);
            }
        }
        #endregion

        #region Secret generation
        private AISIWebhookSecret RequireCurrent()
        {
            AISIWebhookSecret? row = Secrets.Current;
            if (row?.WebHookID is null)
            {
                throw new PXException(Messages.SelectWebhookFirst);
            }

            return row;
        }

        private void StoreNewSecret(AISIWebhookSecret row, bool rotate)
        {
            if (rotate)
            {
                if (Secrets.Cache.IsDirty)
                {
                    throw new PXException(Messages.SaveBeforeRotating);
                }

                AISIWebhookSecret? stored = ErpSecretProvider.SelectDecrypted(row.WebHookID!.Value);
                if (stored is null || string.IsNullOrEmpty(stored.Secret))
                {
                    throw new PXException(Messages.NothingToRotate);
                }

                if (!string.IsNullOrEmpty(stored.RotatingSecret) && stored.RotatingExpiresOn is DateTime ends && ends > DateTime.UtcNow)
                {
                    throw new PXException(Messages.RotationInProgress, ends);
                }

                Secrets.Cache.SetValueExt<AISIWebhookSecret.rotatingSecret>(row, stored.Secret);
                Secrets.Cache.SetValueExt<AISIWebhookSecret.rotatingExpiresOn>(row, DateTime.UtcNow.AddDays(RotationOverlapDays));
            }

            string generated = SecretGenerator.Generate(SecretEncodingListAttribute.ToEncoding(row.SecretEncoding));
            Secrets.Cache.SetValueExt<AISIWebhookSecret.secret>(row, generated);
            Secrets.Update(row);
            Actions.PressSave();

            Reveal.Cache.Clear();
            AISIWebhookSecretReveal reveal = Reveal.Current;
            reveal.NewSecret = generated;
            Reveal.Update(reveal);
        }

        private IEnumerable RevealOnce(PXAdapter adapter)
        {
            Reveal.AskExt();
            Reveal.Cache.Clear();
            return adapter.Get();
        }
        #endregion

        #region Validation
        private void EnsureDecodable(AISIWebhookSecret row)
        {
            SecretEncoding encoding = SecretEncodingListAttribute.ToEncoding(row.SecretEncoding);

            bool reencoded = Secrets.Cache.GetStatus(row) == PXEntryStatus.Updated
                && !Equals(Secrets.Cache.GetValueOriginal<AISIWebhookSecret.secretEncoding>(row), row.SecretEncoding);
            AISIWebhookSecret? stored = reencoded ? ErpSecretProvider.SelectDecrypted(row.WebHookID!.Value) : null;

            EnsureDecodable<AISIWebhookSecret.secret>(row, encoding, stored?.Secret);
            EnsureDecodable<AISIWebhookSecret.rotatingSecret>(row, encoding, stored?.RotatingSecret);
        }

        private void EnsureDecodable<TField>(AISIWebhookSecret row, SecretEncoding encoding, string? stored)
            where TField : IBqlField
        {
            object? value = Secrets.Cache.GetValue<TField>(row);
            bool edited = Secrets.Cache.GetStatus(row) == PXEntryStatus.Inserted
                || !Equals(value, Secrets.Cache.GetValueOriginal<TField>(row));
            string? text = edited ? value as string : stored;

            if (string.IsNullOrEmpty(text))
            {
                return;
            }

            try
            {
                WebhookSecret.Parse(text!, encoding);
            }
            catch (FormatException failure)
            {
                string fieldLabel = PXUIFieldAttribute.GetDisplayName<TField>(Secrets.Cache);
                Secrets.Cache.RaiseExceptionHandling<TField>(
                    row,
                    null,
                    new PXSetPropertyException(row, Messages.SecretNotDecodable, fieldLabel, failure.Message));

                throw new PXException(Messages.SecretNotDecodable, fieldLabel, failure.Message);
            }
        }

        private static void RejectOverlongSecret<TField>(PXCache cache, AISIWebhookSecret? row, object? newValue)
            where TField : IBqlField
        {
            if (newValue is string text && text.Length > AISIWebhookSecret.SecretLength)
            {
                throw new PXSetPropertyException(
                    row,
                    Messages.SecretTooLong,
                    PXUIFieldAttribute.GetDisplayName<TField>(cache),
                    AISIWebhookSecret.SecretLength,
                    text.Length);
            }
        }
        #endregion
    }
}
