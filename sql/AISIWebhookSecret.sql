-- Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.
--
-- Backing table for AISI.AcumaticaWebhookAuthenticator.Acumatica.DAC.AISIWebhookSecret.
-- Run on a development database; in a customization project deliver the same schema as the
-- project's Table entry so publish creates it.
--
-- Secret and RotatingSecret hold [PXRSACryptString] ciphertext, not plaintext. Ciphertext is
-- several times the plaintext (base64 over UTF-16, plus RSA block padding), so the columns are
-- budgeted for a 255-char plaintext under site keys up to 4096 bits; the maintenance graph
-- enforces the 255-char plaintext limit on entry.

CREATE TABLE [dbo].[AISIWebhookSecret] (
    [CompanyID]              INT              NOT NULL DEFAULT 0,
    [WebHookID]              UNIQUEIDENTIFIER NOT NULL,
    [Secret]                 NVARCHAR(2048)   NULL,
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
