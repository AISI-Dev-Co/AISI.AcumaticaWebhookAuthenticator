// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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

        public PXAction<AISIWebhookRetry> Discard = null!;

        // Modern UI shows a custom action only when it is placed on the main toolbar explicitly.
        [PXButton(CommitChanges = true, DisplayOnMainToolbar = true)]
        // Update rather than Delete rights, because a processing view disallows deletes on its cache and would disable the button.
        [PXUIField(DisplayName = "Discard", MapEnableRights = PXCacheRights.Update, MapViewRights = PXCacheRights.Update)]
        protected virtual IEnumerable discard(PXAdapter adapter)
        {
            List<int> selected = Retries.Cache.Cached
                .Cast<AISIWebhookRetry>()
                .Where(row => row.Selected == true && row.RetryID is int)
                .Select(row => row.RetryID!.Value)
                .ToList();

            if (selected.Count == 0)
            {
                throw new PXException(Messages.SelectRetriesFirst);
            }

            if (Retries.Ask(Messages.DiscardConfirm, MessageButtons.YesNo) != WebDialogResult.Yes)
            {
                return adapter.Get();
            }

            PXGraph.CreateInstance<AISIWebhookRetryStore>().Discard(selected);

            Retries.Cache.Clear();
            Retries.Cache.ClearQueryCache();
            return adapter.Get();
        }
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

            // Re-read so a row discarded or retried by someone else since the grid loaded is never replayed.
            AISIWebhookRetry? current = PXGraph.CreateInstance<AISIWebhookRetryStore>().FindCurrent(retryId);
            if (current?.Status != AISIWebhookRetry.StatusPending)
            {
                throw new PXException(Messages.RetryNotPending, retryId);
            }

            AuthenticatedWebhookHandlerBase handler = CreateHandler(current.HandlerType);
            byte[] body = current.Body ?? Array.Empty<byte>();
            ReplayWebhookContext replay = new ReplayWebhookContext(current.WebHookID!.Value, body, current.Method, current.ContentType, current.TraceIdentifier);

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
