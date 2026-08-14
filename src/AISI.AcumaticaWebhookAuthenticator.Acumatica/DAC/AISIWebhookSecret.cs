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
    /// <summary>
    /// The signing secret for one webhook registration, one row per <c>WebHook</c> row.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Secrets are stored via <c>[PXRSACryptString]</c> — Acumatica's own pattern for third-party
    /// integration credentials (the WooCommerce connector's <c>BCBindingWooCommerce</c> stores its
    /// API secret the same way): encrypted at rest with the site certificate, editable by an
    /// administrator without a redeployment, and working unchanged on SaaS where there is no file
    /// system.
    /// </para>
    /// <para>
    /// This table carries <em>only</em> secret material. The handler type lives in
    /// <c>WebHook.Handler</c>, the scheme lives in the handler's code; duplicating either here
    /// would create a second copy to drift.
    /// </para>
    /// </remarks>
    [Serializable]
    [PXCacheName("Webhook Secret")]
    public class AISIWebhookSecret : PXBqlTable, IBqlTable
    {
        /// <summary>
        /// The crypt columns' declared length. The maintenance graph validates against the same
        /// constant, so widening the column cannot silently reintroduce truncation.
        /// </summary>
        public const int SecretLength = 255;

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
        [PXRSACryptString(SecretLength)]
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
        [PXRSACryptString(SecretLength)]
        [PXUIField(DisplayName = "Rotating Secret")]
        public virtual string? RotatingSecret { get; set; }
        public abstract class rotatingSecret : BqlString.Field<rotatingSecret> { }
        #endregion

        #region RotatingExpiresOn
        /// <summary>
        /// When the rotation overlap ends, in UTC. After this instant the rotating secret is no
        /// longer accepted, so a forgotten rotation closes itself.
        /// </summary>
        [PXDBDateAndTime(DisplayNameDate = "Rotation Ends (UTC)", DisplayNameTime = "Rotation End Time (UTC)")]
        [PXUIField(DisplayName = "Rotation Ends (UTC)")]
        public virtual DateTime? RotatingExpiresOn { get; set; }
        public abstract class rotatingExpiresOn : BqlDateTime.Field<rotatingExpiresOn> { }
        #endregion

        #region AllowedAddresses
        /// <summary>
        /// IP addresses and CIDR blocks the sender may call from, comma-separated
        /// (<c>203.0.113.0/24, 2001:db8::/32</c>). Blank means no IP restriction. Not encrypted —
        /// an allowlist is policy, not credential. Only meaningful behind a trusted front proxy
        /// that controls <see cref="ClientAddressHeader"/>; see the library README.
        /// </summary>
        [PXDBString(500, IsUnicode = false)]
        [PXUIField(DisplayName = "Allowed IP Addresses")]
        public virtual string? AllowedAddresses { get; set; }
        public abstract class allowedAddresses : BqlString.Field<allowedAddresses> { }
        #endregion

        #region ClientAddressHeader
        /// <summary>
        /// The header the trusted front proxy records the caller's address in. Used only when
        /// <see cref="AllowedAddresses"/> is set.
        /// </summary>
        [PXDBString(64, IsUnicode = false)]
        [PXDefault(Authentication.IpAllowlistAuthenticator.DefaultClientAddressHeader, PersistingCheck = PXPersistingCheck.Nothing)]
        [PXUIField(DisplayName = "Client Address Header")]
        public virtual string? ClientAddressHeader { get; set; }
        public abstract class clientAddressHeader : BqlString.Field<clientAddressHeader> { }
        #endregion

        #region TrustedProxyDepth
        /// <summary>
        /// How many trailing entries of the header were appended by trusted infrastructure; the
        /// client address is read at exactly this depth from the right. 1 = one trusted proxy.
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
