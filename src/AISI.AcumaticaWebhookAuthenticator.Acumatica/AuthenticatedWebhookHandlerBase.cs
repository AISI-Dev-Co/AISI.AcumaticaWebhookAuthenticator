// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Concurrent;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using AISI.AcumaticaWebhookAuthenticator.Diagnostics;
using PX.Api.Webhooks;
using PX.Data;

namespace AISI.AcumaticaWebhookAuthenticator.Acumatica
{
    /// <summary>An <see cref="IWebhookHandler"/> that authenticates the request before <see cref="ProcessAsync"/> sees it.</summary>
    /// <remarks>
    /// <para>
    /// One authenticator is built per (handler type, webhook registration) on that registration's
    /// first request and reused; a misconfiguration throws on every request rather than denying
    /// quietly.
    /// </para>
    /// <para>
    /// Every authentication failure gets the same 401; the reason goes to <see cref="PXTrace"/> only.
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// public class PushEventHandler : AuthenticatedWebhookHandlerBase
    /// {
    ///     protected override IWebhookAuthenticator CreateAuthenticator(IWebhookSecretProvider secrets) =&gt;
    ///         new HmacAuthenticator(WebhookAuthPresets.GitHub(secrets));
    ///
    ///     protected override Task ProcessAsync(AuthenticatedWebhookContext context, CancellationToken cancellation)
    ///     {
    ///         // context.Body holds the verified request body.
    ///         return Task.CompletedTask;
    ///     }
    /// }
    /// </code>
    /// </example>
    public abstract class AuthenticatedWebhookHandlerBase : IWebhookHandler
    {
        #region Construction and state
        private static readonly ConcurrentDictionary<(Type HandlerType, Guid WebhookId), RegistrationEntry> Registrations =
            new ConcurrentDictionary<(Type HandlerType, Guid WebhookId), RegistrationEntry>();

        private readonly int _maxBodyLength;

        /// <summary>Creates the handler.</summary>
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
        #endregion

        #region Extension points
        /// <summary>Builds the authenticator for one webhook registration, on its first request.</summary>
        /// <param name="secretProvider">
        /// The secret store for this registration. Pass it to the scheme's options; ignore it only
        /// for <see cref="NoneAuthenticator"/>.
        /// </param>
        /// <returns>The authenticator. Must not be null.</returns>
        protected abstract IWebhookAuthenticator CreateAuthenticator(IWebhookSecretProvider secretProvider);

        /// <summary>The business logic. Runs only after the request authenticated.</summary>
        /// <param name="context">The platform context plus the request body buffer. Signature coverage depends on the scheme.</param>
        /// <param name="cancellation">The cancellation token.</param>
        protected abstract Task ProcessAsync(AuthenticatedWebhookContext context, CancellationToken cancellation);

        /// <summary>Where a registration's secrets come from; defaults to <see cref="ErpSecretProvider"/>.</summary>
        /// <param name="webhookId">The registration's <c>WebHook.WebHookID</c>.</param>
        protected virtual IWebhookSecretProvider CreateSecretProvider(Guid webhookId) =>
            new ErpSecretProvider(webhookId);
        #endregion

        #region IWebhookHandler
        /// <inheritdoc/>
        public async Task HandleAsync(WebhookContext context, CancellationToken cancellation)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Body first, so an over-cap request costs no secret read.
            // No ConfigureAwait(false): Acumatica flows tenant and PXTrace context across these awaits.
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

            RegistrationEntry registration = Registrations.GetOrAdd(
                (GetType(), context.Definition.Id),
                BuildRegistration);

            // Applied per request so allowlist edits take effect without rebuilding the authenticator.
            IWebhookAuthenticator authenticator =
                (registration.Provider as IAuthenticatorRefiner)?.Refine(registration.Authenticator)
                ?? registration.Authenticator;

            WebhookAuthContext authContext = WebhookRequestMapper.Map(
                context.Request,
                read.Body,
                DateTimeOffset.UtcNow,
                context.Definition.Id);

            AuthResult result;
            try
            {
                result = authenticator.Authenticate(authContext);
            }
            catch (Exception)
            {
                // Signed junk and overflowed timestamps must be 401, never 500.
                PXTrace.WriteWarning(
                    "Webhook authentication threw (scheme {0}, webhook {1}, trace {2}).",
                    authenticator.Code,
                    context.Definition.Id,
                    context.TraceIdentifier);
                result = AuthResult.Fail(AuthFailureCode.Unspecified);
            }

            if (!result.Succeeded)
            {
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
        #endregion

        #region Internals
        private RegistrationEntry BuildRegistration((Type HandlerType, Guid WebhookId) key)
        {
            IWebhookSecretProvider provider = CreateSecretProvider(key.WebhookId);

            IWebhookAuthenticator authenticator =
                CreateAuthenticator(provider)
                ?? throw new InvalidOperationException(
                    GetType().Name + ".CreateAuthenticator returned null.");

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
            // Status and headers first: the first body write flushes the head and later ones are dropped.
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
        #endregion
    }
}
