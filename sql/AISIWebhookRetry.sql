-- Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

-- Development databases only, because the customization package's Sql item creates this table on publish.

IF OBJECT_ID('dbo.AISIWebhookRetry') IS NULL
BEGIN
    CREATE TABLE [dbo].[AISIWebhookRetry] (
        [CompanyID]              INT              NOT NULL DEFAULT 0,
        [RetryID]                INT              NOT NULL IDENTITY(1,1),
        [WebHookID]              UNIQUEIDENTIFIER NOT NULL,
        [ReceivedOn]             DATETIME         NOT NULL,
        [Status]                 CHAR(1)          NOT NULL DEFAULT 'P',
        [AttemptCount]           INT              NOT NULL DEFAULT 0,
        [LastAttemptOn]          DATETIME         NULL,
        [TraceIdentifier]        VARCHAR(64)      NULL,
        [HandlerType]            VARCHAR(256)     NOT NULL,
        [Method]                 VARCHAR(16)      NULL,
        [ContentType]            VARCHAR(128)     NULL,
        [FailureMessage]         NVARCHAR(1024)   NULL,
        [Body]                   VARBINARY(MAX)   NULL,
        [NoteID]                 UNIQUEIDENTIFIER NULL,
        [Tstamp]                 TIMESTAMP        NOT NULL,
        [CreatedByID]            UNIQUEIDENTIFIER NOT NULL,
        [CreatedByScreenID]      CHAR(8)          NOT NULL,
        [CreatedDateTime]        DATETIME         NOT NULL,
        [LastModifiedByID]       UNIQUEIDENTIFIER NOT NULL,
        [LastModifiedByScreenID] CHAR(8)          NOT NULL,
        [LastModifiedDateTime]   DATETIME         NOT NULL,

        CONSTRAINT [AISIWebhookRetry_PK] PRIMARY KEY CLUSTERED ([CompanyID], [RetryID])
    );

    CREATE INDEX [AISIWebhookRetry_Status] ON [dbo].[AISIWebhookRetry] ([CompanyID], [Status], [ReceivedOn]);
    CREATE INDEX [AISIWebhookRetry_WebHook] ON [dbo].[AISIWebhookRetry] ([CompanyID], [WebHookID]);
END
