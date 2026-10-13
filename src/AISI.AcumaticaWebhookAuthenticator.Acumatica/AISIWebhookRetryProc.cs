// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using AISI.AcumaticaWebhookAuthenticator.Acumatica.DAC;
using PX.Data;
using PX.Data.BQL.Fluent;

namespace AISI.AcumaticaWebhookAuthenticator.Acumatica
{
    /// <summary>Webhook Retries screen (AS301010), which replays stored authenticated bodies through their original handler.</summary>
    public class AISIWebhookRetryProc : PXGraph<AISIWebhookRetryProc>
    {
        #region Selects
        public SelectFrom<AISIWebhookRetry>
            .Where<AISIWebhookRetry.status.IsEqual<AISIWebhookRetry.statusPending>>
            .OrderBy<AISIWebhookRetry.receivedOn.Asc>
            .ProcessingView Retries = null!;
        #endregion

        #region Actions
        public PXCancel<AISIWebhookRetry> Cancel = null!;
        #endregion

        #region Constructors
        public AISIWebhookRetryProc()
        {
            Retries.SetProcessCaption("Retry");
            Retries.SetProcessAllCaption("Retry All");
            Retries.SetAsyncProcessDelegate(RetryPending);
        }
        #endregion

        #region Methods
        // Ticking rows to retry is not a document edit, so the screen must not prompt to save.
        public override bool IsDirty => false;

        /// <summary>Replays each selected row and reports its outcome on the processing screen.</summary>
        public static async Task RetryPending(List<AISIWebhookRetry> rows, CancellationToken cancellation)
        {
            foreach (AISIWebhookRetry row in rows)
            {
                cancellation.ThrowIfCancellationRequested();
                PXProcessing.SetCurrentItem(row);

                try
                {
                    await ReplayAsync(row, cancellation);
                    PXProcessing.SetProcessed();
                }
                catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception failure)
                {
                    PXProcessing.SetError(failure);
                }
            }
        }

        /// <summary>Runs a stored body through its original handler without authenticating again, then records the attempt on the row.</summary>
        public static async Task ReplayAsync(AISIWebhookRetry row, CancellationToken cancellation)
        {
            if (row is null)
            {
                throw new ArgumentNullException(nameof(row));
            }

            int retryId = row.RetryID!.Value;
            AuthenticatedWebhookHandlerBase handler = CreateHandler(row.HandlerType);
            byte[] body = row.Body ?? Array.Empty<byte>();
            var replay = new ReplayWebhookContext(row.WebHookID!.Value, body, row.Method, row.ContentType, row.TraceIdentifier);

            try
            {
                await handler.ReplayAsync(replay, body, cancellation);
            }
            catch (Exception failure) when (!(failure is OperationCanceledException && cancellation.IsCancellationRequested))
            {
                RecordFailure(retryId, failure);
                throw;
            }

            PXGraph.CreateInstance<AISIWebhookRetryStore>().MarkSucceeded(retryId);
        }

        /// <summary>Stores a failed replay on its row, tracing rather than throwing so the original failure is the one reported.</summary>
        private static void RecordFailure(int retryId, Exception failure)
        {
            try
            {
                PXGraph.CreateInstance<AISIWebhookRetryStore>().MarkFailedAgain(retryId, failure.Message);
            }
            catch (Exception persistFailure)
            {
                PXTrace.WriteError("Retry {0}: processing failed and the row could not be updated. {1}", retryId, persistFailure);
            }
        }

        /// <summary>Instantiates the stored handler type, resolving it only from assemblies already loaded so a row can never load new code.</summary>
        private static AuthenticatedWebhookHandlerBase CreateHandler(string? handlerTypeName)
        {
            Type? type = string.IsNullOrEmpty(handlerTypeName) ? null : ResolveLoadedType(handlerTypeName!);
            if (type is null)
            {
                throw new PXException(Messages.RetryHandlerMissing, handlerTypeName);
            }

            if (type.IsAbstract || !typeof(AuthenticatedWebhookHandlerBase).IsAssignableFrom(type))
            {
                throw new PXException(Messages.RetryHandlerInvalid, handlerTypeName);
            }

            try
            {
                return (AuthenticatedWebhookHandlerBase)Activator.CreateInstance(type);
            }
            catch (MemberAccessException failure)
            {
                throw new PXException(failure, Messages.RetryHandlerInvalid, handlerTypeName);
            }
        }

        /// <summary>Finds a type by full name across the assemblies loaded in this AppDomain.</summary>
        private static Type? ResolveLoadedType(string fullName)
        {
            foreach (Assembly assembly in AppDomain.CurrentDomain.GetAssemblies())
            {
                Type? type;
                try
                {
                    type = assembly.GetType(fullName, throwOnError: false, ignoreCase: false);
                }
                catch (Exception failure) when (failure is FileNotFoundException || failure is FileLoadException || failure is NotSupportedException)
                {
                    // One assembly with unresolvable dependencies must not hide a handler that lives in another.
                    continue;
                }

                if (type is object)
                {
                    return type;
                }
            }

            return null;
        }
        #endregion
    }
}
