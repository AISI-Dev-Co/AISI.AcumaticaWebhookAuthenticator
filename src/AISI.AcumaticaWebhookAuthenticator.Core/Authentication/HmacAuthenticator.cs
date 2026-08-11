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
    /// <para>
    /// Covers both the <c>HMAC</c> and <c>HMACTS</c> schemes. They differ only in whether a
    /// timestamp participates, so they are one implementation rather than two near-identical ones;
    /// <see cref="Code"/> still reports them separately.
    /// </para>
    /// <para>
    /// The configuration is snapshotted at construction. <see cref="HmacAuthOptions"/> is a mutable
    /// object-initializer bag, and reading it per request would let a later assignment to
    /// <see cref="HmacAuthOptions.Template"/> or <see cref="HmacAuthOptions.Timestamp"/> walk
    /// straight past the constructor's coherence check — which is precisely the check standing
    /// between a replay window and a timestamp nothing signs. Instances are immutable and safe to
    /// share across threads.
    /// </para>
    /// </remarks>
    public sealed class HmacAuthenticator : IWebhookAuthenticator
    {
        private readonly IWebhookSecretProvider _secretProvider;
        private readonly string _signatureHeader;
        private readonly HmacAlgorithm _algorithm;
        private readonly SignatureEncoding _encoding;
        private readonly string? _signaturePrefix;
        private readonly SignatureExtraction _extraction;
        private readonly SignedPayloadTemplate _template;
        private readonly TimestampValidation? _timestamp;

        /// <summary>
        /// Creates an authenticator.
        /// </summary>
        /// <param name="options">Scheme configuration. Read once, here.</param>
        /// <exception cref="ArgumentNullException"><paramref name="options"/> is null.</exception>
        /// <exception cref="ArgumentException">
        /// The configuration is incoherent, as described by
        /// <see cref="HmacAuthOptions.DescribeMisconfiguration"/>. Chiefly: a replay window over a
        /// timestamp the template does not sign is security theatre, since the signature does not
        /// cover it and a replayer rewrites it freely.
        /// </exception>
        public HmacAuthenticator(HmacAuthOptions options)
        {
            if (options is null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            string? problem = options.DescribeMisconfiguration();
            if (problem is object)
            {
                throw new ArgumentException(problem, nameof(options));
            }

            _secretProvider = options.SecretProvider;
            _signatureHeader = options.SignatureHeader;
            _algorithm = options.Algorithm;
            _encoding = options.Encoding;
            _signaturePrefix = options.SignaturePrefix;
            _extraction = options.Extraction;
            _template = options.Template;
            _timestamp = options.Timestamp;
        }

        /// <inheritdoc/>
        public string Code => _timestamp is null ? "HMAC" : "HMACTS";

        /// <inheritdoc/>
        public AuthResult Authenticate(WebhookAuthContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (!context.TryGetHeader(_signatureHeader, out string headerValue))
            {
                return AuthResult.Fail(AuthFailureCode.SignatureHeaderMissing);
            }

            IReadOnlyList<string> candidates = _extraction.Extract(headerValue);
            if (candidates.Count == 0)
            {
                return AuthResult.Fail(AuthFailureCode.SignatureElementMissing);
            }

            string? timestampRaw = _timestamp?.ReadRaw(context, headerValue);

            TemplateResolution resolution = _template.Resolve(context, timestampRaw);
            if (!resolution.Success)
            {
                return AuthResult.Fail(resolution.FailureCode);
            }

            WebhookSecret? secret = _secretProvider.GetSecret();
            if (secret is null)
            {
                // A missing secret denies the request. It never degrades to unauthenticated
                // handling, which would turn a blank secret field into an open endpoint.
                return AuthResult.Fail(AuthFailureCode.SecretUnavailable);
            }

            var decoded = new List<byte[]>(candidates.Count);
            string rejectionCode = AuthFailureCode.SignatureMismatch;

            foreach (string candidate in candidates)
            {
                if (!TryStripPrefix(candidate, out string encodedSignature))
                {
                    if (decoded.Count == 0)
                    {
                        rejectionCode = AuthFailureCode.SignaturePrefixMismatch;
                    }

                    continue;
                }

                if (!SignatureCodec.TryDecode(encodedSignature, _encoding, out byte[] provided))
                {
                    if (decoded.Count == 0)
                    {
                        rejectionCode = AuthFailureCode.SignatureMalformed;
                    }

                    continue;
                }

                decoded.Add(provided);
            }

            if (decoded.Count == 0)
            {
                return AuthResult.Fail(rejectionCode);
            }

            if (!secret.MatchesAny(_algorithm, resolution.Bytes, decoded, context.ReceivedOn))
            {
                return AuthResult.Fail(AuthFailureCode.SignatureMismatch);
            }

            // Only now is the timestamp trustworthy. Validating the window earlier would mean acting
            // on a value nothing has vouched for.
            return _timestamp is null
                ? AuthResult.Success()
                : _timestamp.Validate(timestampRaw, context.ReceivedOn);
        }

        private bool TryStripPrefix(string candidate, out string signature)
        {
            if (string.IsNullOrEmpty(_signaturePrefix))
            {
                signature = candidate;
                return true;
            }

            if (!candidate.StartsWith(_signaturePrefix!, StringComparison.Ordinal))
            {
                signature = string.Empty;
                return false;
            }

            signature = candidate.Substring(_signaturePrefix!.Length);
            return true;
        }
    }
}
