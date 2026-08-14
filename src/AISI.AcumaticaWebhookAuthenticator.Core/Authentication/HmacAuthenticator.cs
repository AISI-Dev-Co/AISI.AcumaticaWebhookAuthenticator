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

        /// <summary>
        /// The signed-payload template this authenticator verifies against — the snapshot taken at
        /// construction, not whatever <see cref="HmacAuthOptions.Template"/> holds now. Exposed so a
        /// host that cannot satisfy a token can reject the configuration up front: the Acumatica
        /// adapter refuses a <see cref="SignedPayloadTemplate.ReferencesPath"/> template at handler
        /// construction, because the platform surfaces no request path and every request would
        /// otherwise fail at runtime.
        /// </summary>
        public SignedPayloadTemplate Template => _template;

        /// <inheritdoc/>
        public AuthResult Authenticate(WebhookAuthContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (!context.TryGetHeaderValues(_signatureHeader, out IReadOnlyList<string> headerValues))
            {
                return AuthResult.Fail(AuthFailureCode.SignatureHeaderMissing);
            }

            WebhookSecret? secret = _secretProvider.GetSecret();
            if (secret is null)
            {
                // A missing secret denies the request. It never degrades to unauthenticated
                // handling, which would turn a blank secret field into an open endpoint.
                return AuthResult.Fail(AuthFailureCode.SecretUnavailable);
            }

            // A timestamp read out of the signature header belongs to one header value, and the
            // header may have arrived more than once. Each value's signatures must then verify
            // against the payload built from that value's own timestamp — pairing every candidate
            // with the first value's timestamp would make a legitimately signed second value
            // unverifiable. A timestamp from its own header (or no timestamp) is shared by all
            // values, so those schemes verify everything against one resolution.
            if (_timestamp is object && _timestamp.ReadsFromSignatureHeader)
            {
                return AuthenticatePerHeaderValue(context, headerValues, secret);
            }

            string? timestampRaw = _timestamp?.ReadRaw(context, headerValues);

            TemplateResolution resolution = _template.Resolve(context, timestampRaw);
            if (!resolution.Success)
            {
                return AuthResult.Fail(resolution.FailureCode);
            }

            var rejection = new RejectionTracker();
            List<byte[]> decoded = DecodeCandidates(_extraction.Extract(headerValues), rejection);

            if (decoded.Count == 0)
            {
                return AuthResult.Fail(rejection.Code);
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

        private AuthResult AuthenticatePerHeaderValue(
            WebhookAuthContext context,
            IReadOnlyList<string> headerValues,
            WebhookSecret secret)
        {
            var rejection = new RejectionTracker();

            foreach (string headerValue in headerValues)
            {
                IReadOnlyList<string> candidates = _extraction.Extract(headerValue);
                if (candidates.Count == 0)
                {
                    continue;
                }

                string? timestampRaw = _timestamp!.ReadRaw(context, new[] { headerValue });

                TemplateResolution resolution = _template.Resolve(context, timestampRaw);
                if (!resolution.Success)
                {
                    rejection.Consider(RejectionTracker.StageTemplate, resolution.FailureCode);
                    continue;
                }

                List<byte[]> decoded = DecodeCandidates(candidates, rejection);
                if (decoded.Count == 0)
                {
                    continue;
                }

                if (secret.MatchesAny(_algorithm, resolution.Bytes, decoded, context.ReceivedOn))
                {
                    // The window is checked against the timestamp that produced the matching
                    // payload — not against whichever value happened to carry the freshest one.
                    return _timestamp.Validate(timestampRaw, context.ReceivedOn);
                }

                rejection.Consider(RejectionTracker.StageCompare, AuthFailureCode.SignatureMismatch);
            }

            return AuthResult.Fail(rejection.Code);
        }

        private List<byte[]> DecodeCandidates(IReadOnlyList<string> candidates, RejectionTracker rejection)
        {
            var decoded = new List<byte[]>(candidates.Count);

            foreach (string candidate in candidates)
            {
                if (!TryStripPrefix(candidate, out string encodedSignature))
                {
                    rejection.Consider(RejectionTracker.StagePrefix, AuthFailureCode.SignaturePrefixMismatch);
                    continue;
                }

                if (!SignatureCodec.TryDecode(encodedSignature, _encoding, out byte[] provided))
                {
                    rejection.Consider(RejectionTracker.StageDecode, AuthFailureCode.SignatureMalformed);
                    continue;
                }

                decoded.Add(provided);
            }

            return decoded;
        }

        /// <summary>
        /// Keeps the diagnostic code from the candidate that progressed furthest through the
        /// pipeline, so the trace names the most specific problem rather than whichever candidate
        /// happened to fail last. A request carrying both a malformed-but-prefixed signature and an
        /// unprefixed one reports "malformed", in either order.
        /// </summary>
        private sealed class RejectionTracker
        {
            public const int StageTemplate = 1;
            public const int StagePrefix = 2;
            public const int StageDecode = 3;
            public const int StageCompare = 4;

            private int _rank = -1;

            public string Code { get; private set; } = AuthFailureCode.SignatureElementMissing;

            public void Consider(int rank, string code)
            {
                if (rank > _rank)
                {
                    _rank = rank;
                    Code = code;
                }
            }
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
