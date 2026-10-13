-- Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

-- Development databases only, because the customization package's Sql item creates this table on publish.
-- The secret columns hold RSA ciphertext, which runs several times a 255-character plaintext under site keys up to 4096 bits.

IF OBJECT_ID('dbo.AISIWebhookSecret') IS NULL
    CREATE TABLE [dbo].[AISIWebhookSecret] (
        [CompanyID]              INT              NOT NULL DEFAULT 0,
        [WebHookID]              UNIQUEIDENTIFIER NOT NULL,
        [Secret]                 NVARCHAR(2048)   NULL,
        [SecretEncoding]         CHAR(1)          NULL,
        [RotatingSecret]         NVARCHAR(2048)   NULL,
        [RotatingExpiresOn]      DATETIME         NULL,
        [AllowedAddresses]       VARCHAR(500)     NULL,
        [ClientAddressHeader]    VARCHAR(64)      NULL,
        [TrustedProxyDepth]      INT              NULL,
        [NoteID]                 UNIQUEIDENTIFIER NULL,
        [Tstamp]                 TIMESTAMP        NOT NULL,
        [CreatedByID]            UNIQUEIDENTIFIER NOT NULL,
        [CreatedByScreenID]      CHAR(8)          NOT NULL,
        [CreatedDateTime]        DATETIME         NOT NULL,
        [LastModifiedByID]       UNIQUEIDENTIFIER NOT NULL,
        [LastModifiedByScreenID] CHAR(8)          NOT NULL,
        [LastModifiedDateTime]   DATETIME         NOT NULL,

        CONSTRAINT [AISIWebhookSecret_PK] PRIMARY KEY CLUSTERED ([CompanyID], [WebHookID])
    );

-- Upgrade from 0.2.0, where a NULL encoding keeps reading as UTF-8.
IF COL_LENGTH('dbo.AISIWebhookSecret', 'SecretEncoding') IS NULL
    ALTER TABLE [dbo].[AISIWebhookSecret] ADD [SecretEncoding] CHAR(1) NULL;
