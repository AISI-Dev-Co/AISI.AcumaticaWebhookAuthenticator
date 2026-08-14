// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Concurrent;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using PX.Api.Webhooks;
using PX.Data;

namespace AISI.AcumaticaWebhookAuthenticator.Acumatica
{
    /// <summary>
    /// An <see cref="IWebhookHandler"/> that authenticates the request before any consumer code
    /// sees it. Inherit, say how to authenticate, and implement the business logic.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <example>
    /// A GitHub-signed webhook whose secret an administrator maintains on the webhook secrets
    /// screen:
    /// <code>
    /// public class PushEventHandler : AuthenticatedWebhookHandlerBase
    /// {
    ///     protected override IWebhookAuthenticator CreateAuthenticator(IWebhookSecretProvider secrets) =&gt;
    ///         new HmacAuthenticator(WebhookAuthPresets.GitHub(secrets));
    ///
    ///     protected override Task ProcessAsync(AuthenticatedWebhookContext context, CancellationToken cancellation)
    ///     {
    ///         // context.Body / context.GetBodyText() is the verified payload.
    ///     }
    /// }
    /// </code>
    /// </example>
    /// </para>
    /// <para>
    /// The secret provider handed to <see cref="CreateAuthenticator"/> is keyed to the webhook
    /// registration the request arrived on (<c>WebhookDefinition.Id</c> =
    /// <c>WebHook.WebHookID</c>), so one handler type registered under several webhooks gets a
    /// separate secret per registration, uniformly stored, with no per-handler storage code.
    /// </para>
    /// <para>
    /// One authenticator is built per webhook registration, on its first request, and cached for
    /// the handler's lifetime. A misconfiguration — an incoherent option set, a <c>{path}</c>
    /// template — therefore throws on the first request rather than at deploy time; it throws
    /// loudly and every time, rather than denying quietly, because a developer error should read as
    /// one and not as a sender problem.
    /// </para>
    /// <para>
    /// Authentication failures are uniform: same 401, same generic body, whatever the reason. The
    /// specific <see cref="Diagnostics.AuthFailureCode"/> goes to <see cref="PXTrace"/> only.
    /// </para>
    /// </remarks>
    public abstract class AuthenticatedWebhookHandlerBase : IWebhookHandler
    {
        private readonly ConcurrentDictionary<Guid, RegistrationEntry> _registrations =
            new ConcurrentDictionary<Guid, RegistrationEntry>();

        private readonly int _maxBodyLength;

        /// <summary>
        /// Creates the handler.
        /// </summary>
        /// <param name="maxBodyLength">
        /// Body cap in bytes. Defaults to the platform's own 1 MB limit; a tighter cap is a
        /// refinement, a looser one is ineffective behind the platform's.
        /// </param>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="maxBodyLength"/> is negative.</exception>
        protected AuthenticatedWebhookHandlerBase(int maxBodyLength = BoundedBodyReader.DefaultMaxLength)
        {
            if (maxBodyLength < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(maxBodyLength), maxBodyLength, "The cap cannot be negative.");
            }

            _maxBodyLength = maxBodyLength;
        }

        /// <summary>
        /// Builds the authenticator for one webhook registration. Called once per registration, on
        /// its first request.
        /// </summary>
        /// <param name="secretProvider">
        /// The secret store for this registration. Pass it to the scheme's options; ignore it only
        /// for <see cref="NoneAuthenticator"/>.
        /// </param>
        /// <returns>The authenticator. Must not be null.</returns>
        protected abstract IWebhookAuthenticator CreateAuthenticator(IWebhookSecretProvider secretProvider);

        /// <summary>
        /// The business logic. Runs only after the request authenticated.
        /// </summary>
        /// <param name="context">The platform context plus the verified body buffer.</param>
        /// <param name="cancellation">The cancellation token.</param>
        /// <returns>A task.</returns>
        protected abstract Task ProcessAsync(AuthenticatedWebhookContext context, CancellationToken cancellation);

        /// <summary>
        /// Where secrets for a webhook registration come from. Defaults to the ERP database via
        /// <see cref="ErpSecretProvider"/>; override to source them elsewhere.
        /// </summary>
        /// <param name="webhookId">The registration's <c>WebHook.WebHookID</c>.</param>
        /// <returns>The provider.</returns>
        protected virtual IWebhookSecretProvider CreateSecretProvider(Guid webhookId) =>
            new ErpSecretProvider(webhookId);

        /// <inheritdoc/>
        public async Task HandleAsync(WebhookContext context, CancellationToken cancellation)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // The body is read before the authenticator is even resolved: an over-cap request is
            // decided by the byte count alone, so it should not cost a secret-provider read.
            // No ConfigureAwait(false) anywhere in this method: Acumatica flows its own context
            // (tenant, PXTrace scope) across awaits, and detaching from it would run everything
            // after the first await - including the consumer's ProcessAsync - outside that
            // context. Acuminator forbids it (PX1099/PX1120) for exactly this reason.
            BoundedBodyRead read = await BoundedBodyReader.ReadAsync(
                context.Request.Body,
                _maxBodyLength,
                context.Request.ContentLength,
                cancellation);

            if (!read.WithinLimit)
            {
                PXTrace.WriteWarning(
                    "Webhook request rejected: body exceeds {0} bytes (webhook {1}, trace {2}).",
                    _maxBodyLength,
                    context.Definition.Id,
                    context.TraceIdentifier);

                Deny(context.Response, 413, "{\"error\":\"payload_too_large\"}", null);
                return;
            }

            RegistrationEntry registration = _registrations.GetOrAdd(
                context.Definition.Id,
                BuildRegistration);

            // Per-request policy (the ERP-configured allowlist) is applied by the provider, not
            // baked in at construction, so an administrator's edit on the secrets screen takes
            // effect on the provider's cache cadence instead of at the next application restart.
            // Asked for as a capability rather than a concrete type, so replacing or decorating
            // the provider cannot silently drop the restriction.
            IWebhookAuthenticator authenticator =
                (registration.Provider as IAuthenticatorRefiner)?.Refine(registration.Authenticator)
                ?? registration.Authenticator;

            WebhookAuthContext authContext = WebhookRequestMapper.Map(
                context.Request,
                read.Body,
                DateTimeOffset.UtcNow);

            AuthResult result = authenticator.Authenticate(authContext);

            if (!result.Succeeded)
            {
                // The code is diagnostic only. It goes to the trace and never to the sender: a 401
                // that distinguishes "malformed" from "mismatched" is a decision oracle.
                PXTrace.WriteWarning(
                    "Webhook authentication failed: {0} (scheme {1}, webhook {2}, trace {3}).",
                    result.FailureCode,
                    authenticator.Code,
                    context.Definition.Id,
                    context.TraceIdentifier);

                Deny(
                    context.Response,
                    401,
                    "{\"error\":\"unauthorized\"}",
                    (authenticator as IChallengeSource)?.Challenge);
                return;
            }

            await ProcessAsync(new AuthenticatedWebhookContext(context, read.Body), cancellation);
        }

        private RegistrationEntry BuildRegistration(Guid webhookId)
        {
            IWebhookSecretProvider provider = CreateSecretProvider(webhookId);

            IWebhookAuthenticator authenticator =
                CreateAuthenticator(provider)
                ?? throw new InvalidOperationException(
                    GetType().Name + ".CreateAuthenticator returned null.");

            // The platform surfaces no request path, so a configuration that signs {path} could
            // never verify a single request. Failing here, once, names the misconfiguration;
            // failing per request would read as a sender problem. Decorators forward the
            // capability, so wrapping cannot hide the dependency.
            if ((authenticator as IRequestPathDependent)?.RequiresRequestPath == true)
            {
                throw new InvalidOperationException(
                    "The " + authenticator.Code + " configuration signs the request path, but " +
                    "Acumatica's WebhookRequest does not expose one, so no request could ever " +
                    "verify. Remove the {path} token from the signed-payload template.");
            }

            return new RegistrationEntry(authenticator, provider);
        }

        private readonly struct RegistrationEntry
        {
            public RegistrationEntry(IWebhookAuthenticator authenticator, IWebhookSecretProvider provider)
            {
                Authenticator = authenticator;
                Provider = provider;
            }

            public IWebhookAuthenticator Authenticator { get; }

            public IWebhookSecretProvider Provider { get; }
        }

        private static void Deny(WebhookResponse response, int statusCode, string body, string? challenge)
        {
            // Status and every header strictly before the first body write: CreateTextWriter
            // flushes the response head, and anything set afterwards drops silently.
            response.StatusCode = statusCode;

            if (challenge is object)
            {
                response.Headers["WWW-Authenticate"] = challenge;
            }

            using (TextWriter writer = response.CreateTextWriter())
            {
                writer.Write(body);
            }
        }
    }
}
