// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using PX.Data;
using PX.Data.BQL;
using PX.Data.ReferentialIntegrity.Attributes;
using WebHook = PX.Api.Webhooks.DAC.WebHook;

namespace AISI.AcumaticaWebhookAuthenticator.Acumatica.DAC
{
    /// <summary>An authenticated webhook body whose processing threw, kept for an administrator to retry on AS301010.</summary>
    [Serializable]
    [PXCacheName("Webhook Retry")]
    public class AISIWebhookRetry : PXBqlTable, IBqlTable
    {
        #region Constants
        public const string StatusPending = "P";
        public const string StatusSucceeded = "S";

        public const int HandlerTypeLength = 256;
        public const int TraceIdentifierLength = 64;
        public const int MethodLength = 16;
        public const int ContentTypeLength = 128;
        public const int FailureMessageLength = 1024;

        public class statusPending : BqlString.Constant<statusPending>
        {
            public statusPending() : base(StatusPending)
            {
            }
        }
        #endregion

        #region Keys
        public class PK : PrimaryKeyOf<AISIWebhookRetry>.By<retryID>
        {
            public static AISIWebhookRetry Find(PXGraph graph, int? retryID, PKFindOptions options = PKFindOptions.None) =>
                FindBy(graph, retryID, options);
        }

        public static class FK
        {
            public class WebHookRegistration : WebHook.PK.ForeignKeyOf<AISIWebhookRetry>.By<webHookID>
            {
            }
        }
        #endregion

        #region Selected
        [PXBool]
        [PXUnboundDefault(false, PersistingCheck = PXPersistingCheck.Nothing)]
        [PXUIField(DisplayName = "Selected")]
        public virtual bool? Selected { get; set; }
        public abstract class selected : BqlBool.Field<selected> { }
        #endregion

        #region RetryID
        [PXDBIdentity(IsKey = true)]
        [PXUIField(DisplayName = "Retry ID", Enabled = false, Visible = false)]
        public virtual int? RetryID { get; set; }
        public abstract class retryID : BqlInt.Field<retryID> { }
        #endregion

        #region WebHookID
        [PXDBGuid]
        [PXDefault]
        [PXUIField(DisplayName = "Webhook", Enabled = false)]
        [PXSelector(
            typeof(Search<WebHook.webHookID>),
            SubstituteKey = typeof(WebHook.name),
            DescriptionField = typeof(WebHook.handler))]
        [PXForeignReference(typeof(FK.WebHookRegistration))]
        public virtual Guid? WebHookID { get; set; }
        public abstract class webHookID : BqlGuid.Field<webHookID> { }
        #endregion

        #region ReceivedOn
        // UseTimeZone = false is required, because the default would shift this UTC instant.
        [PXDBDateAndTime(UseTimeZone = false, DisplayNameDate = "Received (UTC)", DisplayNameTime = "Received Time (UTC)")]
        [PXDefault]
        [PXUIField(DisplayName = "Received (UTC)", Enabled = false)]
        public virtual DateTime? ReceivedOn { get; set; }
        public abstract class receivedOn : BqlDateTime.Field<receivedOn> { }
        #endregion

        #region Status
        [PXDBString(1, IsFixed = true, IsUnicode = false)]
        [PXDefault(StatusPending)]
        [PXStringList(new[] { StatusPending, StatusSucceeded }, new[] { Messages.RetryStatusPending, Messages.RetryStatusSucceeded })]
        [PXUIField(DisplayName = "Status", Enabled = false)]
        public virtual string? Status { get; set; }
        public abstract class status : BqlString.Field<status> { }
        #endregion

        #region AttemptCount
        [PXDBInt]
        [PXDefault(0)]
        [PXUIField(DisplayName = "Attempts", Enabled = false)]
        public virtual int? AttemptCount { get; set; }
        public abstract class attemptCount : BqlInt.Field<attemptCount> { }
        #endregion

        #region LastAttemptOn
        [PXDBDateAndTime(UseTimeZone = false, DisplayNameDate = "Last Attempt (UTC)", DisplayNameTime = "Last Attempt Time (UTC)")]
        [PXUIField(DisplayName = "Last Attempt (UTC)", Enabled = false)]
        public virtual DateTime? LastAttemptOn { get; set; }
        public abstract class lastAttemptOn : BqlDateTime.Field<lastAttemptOn> { }
        #endregion

        #region TraceIdentifier
        [PXDBString(TraceIdentifierLength, IsUnicode = false)]
        [PXUIField(DisplayName = "Trace", Enabled = false)]
        public virtual string? TraceIdentifier { get; set; }
        public abstract class traceIdentifier : BqlString.Field<traceIdentifier> { }
        #endregion

        #region HandlerType
        [PXDBString(HandlerTypeLength, IsUnicode = false)]
        [PXDefault]
        [PXUIField(DisplayName = "Handler", Enabled = false)]
        public virtual string? HandlerType { get; set; }
        public abstract class handlerType : BqlString.Field<handlerType> { }
        #endregion

        #region Method
        [PXDBString(MethodLength, IsUnicode = false)]
        [PXUIField(DisplayName = "Method", Enabled = false)]
        public virtual string? Method { get; set; }
        public abstract class method : BqlString.Field<method> { }
        #endregion

        #region ContentType
        [PXDBString(ContentTypeLength, IsUnicode = false)]
        [PXUIField(DisplayName = "Content Type", Enabled = false)]
        public virtual string? ContentType { get; set; }
        public abstract class contentType : BqlString.Field<contentType> { }
        #endregion

        #region FailureMessage
        [PXDBString(FailureMessageLength, IsUnicode = true)]
        [PXUIField(DisplayName = "Failure", Enabled = false)]
        public virtual string? FailureMessage { get; set; }
        public abstract class failureMessage : BqlString.Field<failureMessage> { }
        #endregion

        #region Body
        // Never shown on the screen, because a webhook body can carry personal or payment data.
        [PXDBBinary]
        [PXUIField(Visible = false, Enabled = false)]
        public virtual byte[]? Body { get; set; }
        public abstract class body : BqlByteArray.Field<body> { }
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
