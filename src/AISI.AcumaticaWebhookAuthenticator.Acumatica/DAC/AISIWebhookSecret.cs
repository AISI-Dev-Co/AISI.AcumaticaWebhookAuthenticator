// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using PX.Data;
using PX.Data.BQL;
using WebHook = PX.Api.Webhooks.DAC.WebHook;

// The DAC pattern requires a public BQL field class per property and the standard audit-field
// block; the property summaries carry the meaning and the boilerplate has none to add. Suppressed
// for this file only.
#pragma warning disable CS1591

namespace AISI.AcumaticaWebhookAuthenticator.Acumatica.DAC
{
    /// <summary>Signing secret and IP allowlist for one webhook registration.</summary>
    [Serializable]
    [PXCacheName("Webhook Secret")]
    public class AISIWebhookSecret : PXBqlTable, IBqlTable
    {
        /// <summary>
        /// The plaintext limit the maintenance graph enforces on entry.
        /// </summary>
        public const int SecretLength = 255;

        /// <summary>Crypt column size. Ciphertext is ~2.7× plaintext plus RSA padding; 255 is not enough.</summary>
        public const int SecretColumnLength = 2048;

        #region WebHookID
        /// <summary>The webhook registration this secret belongs to.</summary>
        [PXDBGuid(IsKey = true)]
        [PXDefault]
        [PXUIField(DisplayName = "Webhook")]
        [PXSelector(
            typeof(Search<WebHook.webHookID>),
            SubstituteKey = typeof(WebHook.name),
            DescriptionField = typeof(WebHook.handler))]
        public virtual Guid? WebHookID { get; set; }
        public abstract class webHookID : BqlGuid.Field<webHookID> { }
        #endregion

        #region Secret
        /// <summary>The active secret, exactly as the sender's dashboard shows it.</summary>
        [PXRSACryptString(SecretColumnLength)]
        [PXDefault]
        [PXUIField(DisplayName = "Secret")]
        public virtual string? Secret { get; set; }
        public abstract class secret : BqlString.Field<secret> { }
        #endregion

        #region RotatingSecret
        /// <summary>
        /// The outgoing secret during a rotation overlap, accepted alongside
        /// <see cref="Secret"/> until <see cref="RotatingExpiresOn"/>.
        /// </summary>
        [PXRSACryptString(SecretColumnLength)]
        [PXUIField(DisplayName = "Rotating Secret")]
        public virtual string? RotatingSecret { get; set; }
        public abstract class rotatingSecret : BqlString.Field<rotatingSecret> { }
        #endregion

        #region RotatingExpiresOn
        /// <summary>When the rotating secret stops being accepted. <c>UseTimeZone = false</c> is required — the default would shift this UTC instant.</summary>
        [PXDBDateAndTime(UseTimeZone = false, DisplayNameDate = "Rotation Ends (UTC)", DisplayNameTime = "Rotation End Time (UTC)")]
        [PXUIField(DisplayName = "Rotation Ends (UTC)")]
        public virtual DateTime? RotatingExpiresOn { get; set; }
        public abstract class rotatingExpiresOn : BqlDateTime.Field<rotatingExpiresOn> { }
        #endregion

        #region AllowedAddresses
        /// <summary>
        /// Comma-separated addresses and CIDR blocks the sender may call from; blank means no IP
        /// restriction. Not encrypted — policy, not credential. Only meaningful behind a trusted
        /// front proxy that controls <see cref="ClientAddressHeader"/>.
        /// </summary>
        [PXDBString(500, IsUnicode = false)]
        [PXUIField(DisplayName = "Allowed IP Addresses")]
        public virtual string? AllowedAddresses { get; set; }
        public abstract class allowedAddresses : BqlString.Field<allowedAddresses> { }
        #endregion

        #region ClientAddressHeader
        /// <summary>The header the trusted proxy records the caller's address in.</summary>
        [PXDBString(64, IsUnicode = false)]
        [PXDefault(Authentication.IpAllowlistAuthenticator.DefaultClientAddressHeader, PersistingCheck = PXPersistingCheck.Nothing)]
        [PXUIField(DisplayName = "Client Address Header")]
        public virtual string? ClientAddressHeader { get; set; }
        public abstract class clientAddressHeader : BqlString.Field<clientAddressHeader> { }
        #endregion

        #region TrustedProxyDepth
        /// <summary>
        /// How many trailing header entries trusted infrastructure appended; the client address is
        /// read at this depth from the right.
        /// </summary>
        [PXDBInt(MinValue = 1, MaxValue = 10)]
        [PXDefault(Authentication.IpAllowlistAuthenticator.DefaultTrustedProxyDepth, PersistingCheck = PXPersistingCheck.Nothing)]
        [PXUIField(DisplayName = "Trusted Proxy Depth")]
        public virtual int? TrustedProxyDepth { get; set; }
        public abstract class trustedProxyDepth : BqlInt.Field<trustedProxyDepth> { }
        #endregion

        #region NoteID
        [PXNote]
        public virtual Guid? NoteID { get; set; }
        public abstract class noteID : BqlGuid.Field<noteID> { }
        #endregion

        #region Tstamp
        [PXDBTimestamp]
        public virtual byte[]? Tstamp { get; set; }
        public abstract class tstamp : BqlByteArray.Field<tstamp> { }
        #endregion

        #region CreatedByID
        [PXDBCreatedByID]
        public virtual Guid? CreatedByID { get; set; }
        public abstract class createdByID : BqlGuid.Field<createdByID> { }
        #endregion

        #region CreatedByScreenID
        [PXDBCreatedByScreenID]
        public virtual string? CreatedByScreenID { get; set; }
        public abstract class createdByScreenID : BqlString.Field<createdByScreenID> { }
        #endregion

        #region CreatedDateTime
        [PXDBCreatedDateTime]
        public virtual DateTime? CreatedDateTime { get; set; }
        public abstract class createdDateTime : BqlDateTime.Field<createdDateTime> { }
        #endregion

        #region LastModifiedByID
        [PXDBLastModifiedByID]
        public virtual Guid? LastModifiedByID { get; set; }
        public abstract class lastModifiedByID : BqlGuid.Field<lastModifiedByID> { }
        #endregion

        #region LastModifiedByScreenID
        [PXDBLastModifiedByScreenID]
        public virtual string? LastModifiedByScreenID { get; set; }
        public abstract class lastModifiedByScreenID : BqlString.Field<lastModifiedByScreenID> { }
        #endregion

        #region LastModifiedDateTime
        [PXDBLastModifiedDateTime]
        public virtual DateTime? LastModifiedDateTime { get; set; }
        public abstract class lastModifiedDateTime : BqlDateTime.Field<lastModifiedDateTime> { }
        #endregion
    }
}
