// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using PX.Data;
using PX.Data.BQL;

namespace AISI.AcumaticaWebhookAuthenticator.Acumatica.DAC
{
    /// <summary>Unbound dialog row that shows a newly generated secret once.</summary>
    [Serializable]
    [PXHidden]
    public class AISIWebhookSecretReveal : PXBqlTable, IBqlTable
    {
        #region NewSecret
        [PXString(IsUnicode = true)]
        [PXUIField(DisplayName = "New Secret")]
        public virtual string? NewSecret { get; set; }
        public abstract class newSecret : BqlString.Field<newSecret> { }
        #endregion
    }
}
