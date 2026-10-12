// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using PX.Data;
using PX.Data.BQL;

#pragma warning disable CS1591

namespace AISI.AcumaticaWebhookAuthenticator.Acumatica.DAC
{
    /// <summary>Shows a generated secret once, in a dialog. Never persisted.</summary>
    [Serializable]
    [PXHidden]
    public class AISIWebhookSecretReveal : PXBqlTable, IBqlTable
    {
        #region NewSecret
        /// <summary>The secret just stored, for the administrator to copy into the sender.</summary>
        [PXString(IsUnicode = true)]
        [PXUIField(DisplayName = "New Secret")]
        public virtual string? NewSecret { get; set; }
        public abstract class newSecret : BqlString.Field<newSecret> { }
        #endregion
    }
}
