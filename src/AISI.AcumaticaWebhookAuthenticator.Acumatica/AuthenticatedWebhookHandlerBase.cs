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
    /// <summary>An <see cref="IWebhookHandler"/> that authenticates each request before <see cref="ProcessAsync"/> sees it.</summary>
    public abstract class AuthenticatedWebhookHandlerBase : IWebhookHandler
    {
        #region Construction and state
        // One authenticator per handler type and registration, built on first request so a misconfiguration throws every time.
        private static readonly ConcurrentDictionary<(Type HandlerType, Guid WebhookId), RegistrationEntry> Registrations =
            new ConcurrentDictionary<(Type HandlerType, Guid WebhookId), RegistrationEntry>();

        private readonly int _maxBodyLength;

        // The default matches the platform's own 1 MB cap, so only a tighter cap has any effect.
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
        /// <summary>Builds the authenticator for one webhook registration from the registration's secret provider.</summary>
        protected abstract IWebhookAuthenticator CreateAuthenticator(IWebhookSecretProvider secretProvider);

        /// <summary>Runs the business logic for a request that has already authenticated.</summary>
        protected abstract Task ProcessAsync(AuthenticatedWebhookContext context, CancellationToken cancellation);

        /// <summary>Creates the secret provider for a registration, defaulting to the Webhook Secrets screen.</summary>
        protected virtual IWebhookSecretProvider CreateSecretProvider(Guid webhookId) =>
            new ErpSecretProvider(webhookId);
        #endregion

        #region IWebhookHandler
        // No ConfigureAwait(false) in here, because Acumatica flows tenant and PXTrace context across these awaits.
        public async Task HandleAsync(WebhookContext context, CancellationToken cancellation)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Body first, so an over-cap request costs no secret read.
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

            // Refined per request so allowlist edits take effect without rebuilding the authenticator.
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
                // The failure reason goes to the trace only, since a sender who can tell failures apart has an oracle.
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
        /// <summary>Creates and validates the authenticator and secret provider for one registration.</summary>
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

        /// <summary>Writes a denial response with an optional WWW-Authenticate challenge.</summary>
        private static void Deny(WebhookResponse response, int statusCode, string body, string? challenge)
        {
            // Status and headers first, because the first body write flushes the head and later header writes are dropped.
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
