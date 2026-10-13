// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using AISI.AcumaticaWebhookAuthenticator.Acumatica.DAC;
using PX.Data;
using PX.Data.BQL.Fluent;

namespace AISI.AcumaticaWebhookAuthenticator.Acumatica
{
    /// <summary>Screenless graph that writes retry rows from the webhook request path and the retry screen.</summary>
    public class AISIWebhookRetryStore : PXGraph<AISIWebhookRetryStore>
    {
        #region Selects
        // Persist only writes caches bound to a view, so the rows need this one even with no screen.
        public SelectFrom<AISIWebhookRetry>.View Retries = null!;
        #endregion

        #region Methods
        /// <summary>Stores an authenticated body whose processing threw as a pending retry.</summary>
        internal void SaveFailure(
            Guid webhookId,
            Type handlerType,
            DateTimeOffset receivedOn,
            string? traceIdentifier,
            string? method,
            string? contentType,
            byte[] body,
            string failureMessage)
        {
            var row = new AISIWebhookRetry
            {
                WebHookID = webhookId,
                HandlerType = Truncate(handlerType.FullName, AISIWebhookRetry.HandlerTypeLength),
                ReceivedOn = receivedOn.UtcDateTime,
                TraceIdentifier = Truncate(traceIdentifier, AISIWebhookRetry.TraceIdentifierLength),
                Method = Truncate(method, AISIWebhookRetry.MethodLength),
                ContentType = Truncate(contentType, AISIWebhookRetry.ContentTypeLength),
                Body = body,
                FailureMessage = Truncate(failureMessage, AISIWebhookRetry.FailureMessageLength),
            };

            // The row must stay Inserted, because an Update before Persist becomes an UPDATE on an identity that does not exist yet.
            if (Retries.Insert(row) is null)
            {
                throw new PXException(Messages.RetryNotSaved);
            }

            Persist();
        }

        internal void MarkSucceeded(int retryId) => RecordAttempt(retryId, succeeded: true, failureMessage: null);

        internal void MarkFailedAgain(int retryId, string failureMessage) => RecordAttempt(retryId, succeeded: false, failureMessage);

        /// <summary>Counts one retry attempt on the row, completing it on success or recording the new failure.</summary>
        private void RecordAttempt(int retryId, bool succeeded, string? failureMessage)
        {
            AISIWebhookRetry? row = AISIWebhookRetry.PK.Find(this, retryId);
            if (row is null)
            {
                throw new PXException(Messages.RetryMissing, retryId);
            }

            row.Status = succeeded ? AISIWebhookRetry.StatusSucceeded : AISIWebhookRetry.StatusPending;
            row.FailureMessage = Truncate(failureMessage, AISIWebhookRetry.FailureMessageLength);
            row.AttemptCount = (row.AttemptCount ?? 0) + 1;
            row.LastAttemptOn = DateTime.UtcNow;
            Retries.Update(row);
            Persist();
        }

        /// <summary>Cuts a value down to its column length so an oversized header never loses the whole retry row.</summary>
        private static string? Truncate(string? value, int maxLength) =>
            value is null || value.Length <= maxLength ? value : value.Substring(0, maxLength);
        #endregion
    }
}
