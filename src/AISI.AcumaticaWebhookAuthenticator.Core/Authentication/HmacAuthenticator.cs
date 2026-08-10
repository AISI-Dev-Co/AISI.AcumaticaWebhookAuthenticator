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
        public HmacAuthenticator(HmacAuthOptions options)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
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

            string? timestampRaw = _options.Timestamp?.ReadRaw(context, headerValue, _options.Extraction);

            TemplateResolution resolution = _options.Template.Resolve(context, timestampRaw);
            if (!resolution.Success)
            {
                return AuthResult.Fail(resolution.FailureCode);
            }

            WebhookSecret? secret = _options.SecretProvider.GetSecret();
            if (secret is null)
            {
                // A missing secret denies the request. It never degrades to unauthenticated
                // handling, which would turn a misconfiguration into an open endpoint.
                return AuthResult.Fail(AuthFailureCode.SecretUnavailable);
            }

            IReadOnlyList<byte[]> keys = secret.CandidatesAsOf(context.ReceivedOn);
            string failureCode = AuthFailureCode.SignatureMismatch;
            bool reachedComparison = false;

            foreach (string candidate in candidates)
            {
                if (!TryStripPrefix(candidate, out string encodedSignature))
                {
                    if (!reachedComparison)
                    {
                        failureCode = AuthFailureCode.SignaturePrefixMismatch;
                    }

                    continue;
                }

                if (!SignatureCodec.TryDecode(encodedSignature, _options.Encoding, out byte[] provided))
                {
                    if (!reachedComparison)
                    {
                        failureCode = AuthFailureCode.SignatureMalformed;
                    }

                    continue;
                }

                reachedComparison = true;
                failureCode = AuthFailureCode.SignatureMismatch;

                foreach (byte[] key in keys)
                {
                    byte[] expected = HmacComputer.Compute(_options.Algorithm, key, resolution.Bytes);

                    if (FixedTimeComparer.AreEqual(expected, provided))
                    {
                        // The signature is only now trustworthy, so the replay window is evaluated
                        // after it and not before: until this point the timestamp is attacker-supplied
                        // data that nothing has vouched for.
                        return _options.Timestamp is null
                            ? AuthResult.Success()
                            : _options.Timestamp.Validate(timestampRaw, context.ReceivedOn);
                    }
                }
            }

            return AuthResult.Fail(failureCode);
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
