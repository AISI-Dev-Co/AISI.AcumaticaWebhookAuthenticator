// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using AISI.AcumaticaWebhookAuthenticator.Diagnostics;
using AISI.AcumaticaWebhookAuthenticator.Signing;

namespace AISI.AcumaticaWebhookAuthenticator.Authentication
{
    /// <summary>
    /// Verifies an HMAC signature over a templated payload, optionally inside a replay window.
    /// </summary>
    /// <remarks>
    /// Covers both the <c>HMAC</c> and <c>HMACTS</c> schemes. They differ only in whether a
    /// timestamp participates, so they are one implementation rather than two near-identical ones;
    /// <see cref="Code"/> still reports them separately.
    /// </remarks>
    public sealed class HmacAuthenticator : IWebhookAuthenticator
    {
        private readonly HmacAuthOptions _options;

        /// <summary>
        /// Creates an authenticator.
        /// </summary>
        /// <param name="options">Scheme configuration.</param>
        /// <exception cref="ArgumentNullException"><paramref name="options"/> is null.</exception>
        /// <exception cref="ArgumentException">
        /// The template and the replay window disagree about whether a timestamp exists. Both
        /// directions are rejected, at construction rather than per request:
        /// <list type="bullet">
        /// <item>
        /// A replay window over a timestamp the template does not sign is security theatre — the
        /// signature does not cover it, so a replayer rewrites it and sails through.
        /// </item>
        /// <item>
        /// A template that signs a timestamp with no window configured would fail every request with
        /// <see cref="AuthFailureCode.TimestampMissing"/>, which reads as a sender problem rather
        /// than the configuration error it is.
        /// </item>
        /// </list>
        /// </exception>
        public HmacAuthenticator(HmacAuthOptions options)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));

            if (options.Timestamp is object && !options.Template.ReferencesTimestamp)
            {
                throw new ArgumentException(
                    "A replay window is configured but the signed-payload template '" +
                    options.Template.Pattern +
                    "' does not include a {timestamp} token, so the signature would not cover the " +
                    "timestamp being validated. Add {timestamp} to the template, or drop the window.",
                    nameof(options));
            }

            if (options.Timestamp is null && options.Template.ReferencesTimestamp)
            {
                throw new ArgumentException(
                    "The signed-payload template '" +
                    options.Template.Pattern +
                    "' includes a {timestamp} token but no timestamp source is configured, so no " +
                    "request could ever be verified. Set HmacAuthOptions.Timestamp.",
                    nameof(options));
            }
        }

        /// <inheritdoc/>
        public string Code => _options.Timestamp is null ? "HMAC" : "HMACTS";

        /// <inheritdoc/>
        public AuthResult Authenticate(WebhookAuthContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (!context.TryGetHeader(_options.SignatureHeader, out string headerValue))
            {
                return AuthResult.Fail(AuthFailureCode.SignatureHeaderMissing);
            }

            IReadOnlyList<string> candidates = _options.Extraction.Extract(headerValue);
            if (candidates.Count == 0)
            {
                return AuthResult.Fail(AuthFailureCode.SignatureElementMissing);
            }

            string? timestampRaw = _options.Timestamp?.ReadRaw(context, headerValue);

            TemplateResolution resolution = _options.Template.Resolve(context, timestampRaw);
            if (!resolution.Success)
            {
                return AuthResult.Fail(resolution.FailureCode);
            }

            WebhookSecret? secret = _options.SecretProvider.GetSecret();
            if (secret is null)
            {
                // A missing secret denies the request. It never degrades to unauthenticated
                // handling, which would turn a blank secret field into an open endpoint.
                return AuthResult.Fail(AuthFailureCode.SecretUnavailable);
            }

            bool matched = false;
            bool anyWellFormed = false;
            string rejectionCode = AuthFailureCode.SignatureMismatch;

            foreach (string candidate in candidates)
            {
                if (!TryStripPrefix(candidate, out string encodedSignature))
                {
                    if (!anyWellFormed)
                    {
                        rejectionCode = AuthFailureCode.SignaturePrefixMismatch;
                    }

                    continue;
                }

                if (!SignatureCodec.TryDecode(encodedSignature, _options.Encoding, out byte[] provided))
                {
                    if (!anyWellFormed)
                    {
                        rejectionCode = AuthFailureCode.SignatureMalformed;
                    }

                    continue;
                }

                anyWellFormed = true;
                matched |= secret.Matches(_options.Algorithm, resolution.Bytes, provided, context.ReceivedOn);
            }

            if (!matched)
            {
                return AuthResult.Fail(anyWellFormed ? AuthFailureCode.SignatureMismatch : rejectionCode);
            }

            // Only now is the timestamp trustworthy. Validating the window earlier would mean acting
            // on a value nothing has vouched for.
            return _options.Timestamp is null
                ? AuthResult.Success()
                : _options.Timestamp.Validate(timestampRaw, context.ReceivedOn);
        }

        private bool TryStripPrefix(string candidate, out string signature)
        {
            string? prefix = _options.SignaturePrefix;

            if (string.IsNullOrEmpty(prefix))
            {
                signature = candidate;
                return true;
            }

            if (!candidate.StartsWith(prefix!, StringComparison.Ordinal))
            {
                signature = string.Empty;
                return false;
            }

            signature = candidate.Substring(prefix!.Length);
            return true;
        }
    }
}
