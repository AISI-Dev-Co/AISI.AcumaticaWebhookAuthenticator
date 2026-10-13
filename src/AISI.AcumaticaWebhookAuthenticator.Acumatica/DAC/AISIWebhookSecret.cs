// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using PX.Data;
using PX.Data.BQL;
using PX.Data.ReferentialIntegrity.Attributes;
using WebHook = PX.Api.Webhooks.DAC.WebHook;

namespace AISI.AcumaticaWebhookAuthenticator.Acumatica.DAC
{
    /// <summary>Signing secret and IP allowlist for one webhook registration.</summary>
    [Serializable]
    [PXCacheName("Webhook Secret")]
    public class AISIWebhookSecret : PXBqlTable, IBqlTable
    {
        #region Constants
        public const int SecretLength = 255;

        // RSA ciphertext is about 2.7 times the plaintext plus padding, so the column must be far wider than SecretLength.
        public const int SecretColumnLength = 2048;
        #endregion

        #region Keys
        public class PK : PrimaryKeyOf<AISIWebhookSecret>.By<webHookID>
        {
            public static AISIWebhookSecret Find(PXGraph graph, Guid? webHookID, PKFindOptions options = PKFindOptions.None) =>
                FindBy(graph, webHookID, options);
        }

        public static class FK
        {
            public class WebHookRegistration : WebHook.PK.ForeignKeyOf<AISIWebhookSecret>.By<webHookID>
            {
            }
        }
        #endregion

        #region WebHookID
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
        [PXRSACryptString(SecretColumnLength)]
        [PXDefault]
        [PXUIField(DisplayName = "Secret")]
        public virtual string? Secret { get; set; }
        public abstract class secret : BqlString.Field<secret> { }
        #endregion

        #region SecretEncoding
        [PXDBString(1, IsFixed = true, IsUnicode = false)]
        [PXDefault(SecretEncodingListAttribute.Utf8, PersistingCheck = PXPersistingCheck.Nothing)]
        [SecretEncodingList]
        [PXUIField(DisplayName = "Secret Encoding")]
        public virtual string? SecretEncoding { get; set; }
        public abstract class secretEncoding : BqlString.Field<secretEncoding> { }
        #endregion

        #region RotatingSecret
        [PXRSACryptString(SecretColumnLength)]
        [PXUIField(DisplayName = "Rotating Secret")]
        public virtual string? RotatingSecret { get; set; }
        public abstract class rotatingSecret : BqlString.Field<rotatingSecret> { }
        #endregion

        #region RotatingExpiresOn
        // UseTimeZone = false is required, because the default would shift this UTC instant.
        [PXDBDateAndTime(UseTimeZone = false, DisplayNameDate = "Rotation Ends (UTC)", DisplayNameTime = "Rotation End Time (UTC)")]
        [PXUIField(DisplayName = "Rotation Ends (UTC)")]
        public virtual DateTime? RotatingExpiresOn { get; set; }
        public abstract class rotatingExpiresOn : BqlDateTime.Field<rotatingExpiresOn> { }
        #endregion

        #region AllowedAddresses
        // Not encrypted, because an allowlist is policy rather than a credential.
        [PXDBString(500, IsUnicode = false)]
        [PXUIField(DisplayName = "Allowed IP Addresses")]
        public virtual string? AllowedAddresses { get; set; }
        public abstract class allowedAddresses : BqlString.Field<allowedAddresses> { }
        #endregion

        #region ClientAddressHeader
        [PXDBString(64, IsUnicode = false)]
        [PXDefault(Authentication.IpAllowlistAuthenticator.DefaultClientAddressHeader, PersistingCheck = PXPersistingCheck.Nothing)]
        [PXUIField(DisplayName = "Client Address Header")]
        public virtual string? ClientAddressHeader { get; set; }
        public abstract class clientAddressHeader : BqlString.Field<clientAddressHeader> { }
        #endregion

        #region TrustedProxyDepth
        // The number of trailing header entries appended by trusted proxies, so the client address is read that far from the right.
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
