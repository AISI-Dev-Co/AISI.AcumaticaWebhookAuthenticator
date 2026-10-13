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
    /// <summary>Webhook Secrets screen (AS301000), where stored secrets are write-only and a generated one is shown once.</summary>
    public class AISIWebhookSecretMaint : PXGraph<AISIWebhookSecretMaint, AISIWebhookSecret>
    {
        #region Constants
        public const int RotationOverlapDays = 7;
        #endregion

        #region Selects
        public SelectFrom<AISIWebhookSecret>.View Secrets = null!;

        public PXFilter<AISIWebhookSecretReveal> Reveal = null!;
        #endregion

        #region Actions
        public PXAction<AISIWebhookSecret> GenerateSecret = null!;

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

        public PXAction<AISIWebhookSecret> RotateSecret = null!;

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

        #region Events
        protected virtual void _(Events.FieldVerifying<AISIWebhookSecret, AISIWebhookSecret.secret> e)
        {
            RejectOverlongSecret<AISIWebhookSecret.secret>(e.Cache, e.Row, e.NewValue);
        }

        protected virtual void _(Events.FieldVerifying<AISIWebhookSecret, AISIWebhookSecret.rotatingSecret> e)
        {
            RejectOverlongSecret<AISIWebhookSecret.rotatingSecret>(e.Cache, e.Row, e.NewValue);
        }

        protected virtual void _(Events.FieldVerifying<AISIWebhookSecret, AISIWebhookSecret.allowedAddresses> e)
        {
            if (!(e.NewValue is string text) || string.IsNullOrWhiteSpace(text))
            {
                return;
            }

            // Same parser as the request path, so a typo is a red field here instead of denying every request later.
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
                // ParseCsv throws ArgumentException only when the text holds separators but no entries.
                throw new PXSetPropertyException(e.Row, Messages.AllowlistEmpty);
            }
        }

        protected virtual void _(Events.RowPersisting<AISIWebhookSecret> e)
        {
            if (e.Row is null || e.Operation == PXDBOperation.Delete)
            {
                return;
            }

            bool hasRotating = !string.IsNullOrEmpty(e.Row.RotatingSecret);
            bool hasExpiry = e.Row.RotatingExpiresOn is object;

            // RaiseExceptionHandling only marks the field red, so the throw is what blocks the save.
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

        #region Methods
        public override void Persist()
        {
            foreach (AISIWebhookSecret row in Secrets.Cache.Inserted.Cast<AISIWebhookSecret>()
                .Concat(Secrets.Cache.Updated.Cast<AISIWebhookSecret>()))
            {
                EnsureDecodable(row);
            }

            base.Persist();
        }

        /// <summary>Returns the selected secret row, or throws when no webhook is selected.</summary>
        private AISIWebhookSecret RequireCurrent()
        {
            AISIWebhookSecret? row = Secrets.Current;
            if (row?.WebHookID is null)
            {
                throw new PXException(Messages.SelectWebhookFirst);
            }

            return row;
        }

        /// <summary>Saves a freshly generated secret on the row, optionally keeping the stored one live as the rotating secret.</summary>
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

        /// <summary>Shows the generated-secret dialog, then clears it so the secret cannot be shown again.</summary>
        private IEnumerable RevealOnce(PXAdapter adapter)
        {
            Reveal.AskExt();
            Reveal.Cache.Clear();
            return adapter.Get();
        }

        /// <summary>Throws when either secret on the row does not decode under the row's encoding.</summary>
        private void EnsureDecodable(AISIWebhookSecret row)
        {
            SecretEncoding encoding = SecretEncodingListAttribute.ToEncoding(row.SecretEncoding);

            // An encoding-only change must re-check the stored secrets, which this cache holds encrypted.
            bool reencoded = Secrets.Cache.GetStatus(row) == PXEntryStatus.Updated
                && !Equals(Secrets.Cache.GetValueOriginal<AISIWebhookSecret.secretEncoding>(row), row.SecretEncoding);
            AISIWebhookSecret? stored = reencoded ? ErpSecretProvider.SelectDecrypted(row.WebHookID!.Value) : null;

            EnsureDecodable<AISIWebhookSecret.secret>(row, encoding, stored?.Secret);
            EnsureDecodable<AISIWebhookSecret.rotatingSecret>(row, encoding, stored?.RotatingSecret);
        }

        /// <summary>Marks the field and throws when its edited or stored value does not decode under the encoding.</summary>
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

        /// <summary>Rejects a secret longer than the column holds, since a silently truncated secret would never verify.</summary>
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
