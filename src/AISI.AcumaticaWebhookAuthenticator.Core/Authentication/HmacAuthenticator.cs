// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using AISI.AcumaticaWebhookAuthenticator.Diagnostics;
using AISI.AcumaticaWebhookAuthenticator.Signing;

namespace AISI.AcumaticaWebhookAuthenticator.Authentication
{
    /// <summary>
    /// Verifies an HMAC signature over a templated payload (<c>HMAC</c>), optionally inside a replay
    /// window (<c>HMACTS</c>). The options are snapshotted at construction; instances are immutable.
    /// </summary>
    public sealed class HmacAuthenticator : IWebhookAuthenticator, IRequestPathDependent
    {
        #region Construction and state
        private readonly IWebhookSecretProvider _secretProvider;
        private readonly string _signatureHeader;
        private readonly HmacAlgorithm _algorithm;
        private readonly SignatureEncoding _encoding;
        private readonly string? _signaturePrefix;
        private readonly SignatureExtraction _extraction;
        private readonly SignedPayloadTemplate _template;
        private readonly TimestampValidation? _timestamp;

        /// <summary>Creates an authenticator.</summary>
        /// <param name="options">Scheme configuration. Read once, here.</param>
        /// <exception cref="ArgumentNullException"><paramref name="options"/> is null.</exception>
        /// <exception cref="ArgumentException">
        /// The configuration is incoherent, as described by <see cref="HmacAuthOptions.DescribeMisconfiguration"/>.
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

            // Copied, not read per request, so a later assignment cannot bypass the coherence check above.
            _secretProvider = options.SecretProvider;
            _signatureHeader = options.SignatureHeader;
            _algorithm = options.Algorithm;
            _encoding = options.Encoding;
            _signaturePrefix = options.SignaturePrefix;
            _extraction = options.Extraction;
            _template = options.Template;
            _timestamp = options.Timestamp;
        }
        #endregion

        #region Authentication
        /// <inheritdoc/>
        public string Code => _timestamp is null ? "HMAC" : "HMACTS";

        /// <summary>Whether the template signs <c>{path}</c>, which a host with no request path must reject up front.</summary>
        public bool RequiresRequestPath => _template.ReferencesPath;

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
                // Fail closed: a blank secret field must never become an open endpoint.
                return AuthResult.Fail(AuthFailureCode.SecretUnavailable);
            }

            var rejection = new RejectionTracker();

            foreach (SignatureGroup group in GroupCandidates(context, headerValues, _extraction, _timestamp))
            {
                TemplateResolution resolution = _template.Resolve(context, group.TimestampRaw);
                if (!resolution.Success)
                {
                    rejection.Consider(RejectionTracker.StageTemplate, resolution.FailureCode);
                    continue;
                }

                List<byte[]> decoded = DecodeCandidates(group.Candidates, rejection);
                if (decoded.Count == 0)
                {
                    continue;
                }

                if (secret.MatchesAny(_algorithm, resolution.Bytes, decoded, context.ReceivedOn))
                {
                    // Only a verified timestamp is trusted, and it must be the one this group was signed over.
                    return _timestamp is null
                        ? AuthResult.Success()
                        : _timestamp.Validate(group.TimestampRaw, context.ReceivedOn);
                }

                rejection.Consider(RejectionTracker.StageCompare, AuthFailureCode.SignatureMismatch);
            }

            return AuthResult.Fail(rejection.Code);
        }
        #endregion

        #region Internals
        /// <summary>
        /// Pairs signature candidates with the timestamp they were signed over: one group per signature
        /// header value when the timestamp lives in that header, otherwise one group for the request.
        /// </summary>
        internal static IEnumerable<SignatureGroup> GroupCandidates(
            WebhookAuthContext context,
            IReadOnlyList<string> headerValues,
            SignatureExtraction extraction,
            TimestampValidation? timestamp)
        {
            if (timestamp is null || !timestamp.ReadsFromSignatureHeader)
            {
                yield return new SignatureGroup(extraction.Extract(headerValues), timestamp?.ReadRaw(context, headerValues));
                yield break;
            }

            foreach (string headerValue in headerValues)
            {
                IReadOnlyList<string> candidates = extraction.Extract(headerValue);
                if (candidates.Count == 0)
                {
                    continue;
                }

                yield return new SignatureGroup(candidates, timestamp.ReadRaw(context, new[] { headerValue }));
            }
        }

        private List<byte[]> DecodeCandidates(IReadOnlyList<string> candidates, RejectionTracker rejection)
        {
            var decoded = new List<byte[]>(candidates.Count);

            foreach (string candidate in candidates)
            {
                if (!CredentialVerifier.TryStripPrefix(candidate, _signaturePrefix, out string encodedSignature))
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

        internal readonly struct SignatureGroup
        {
            public SignatureGroup(IReadOnlyList<string> candidates, string? timestampRaw)
            {
                Candidates = candidates;
                TimestampRaw = timestampRaw;
            }

            public IReadOnlyList<string> Candidates { get; }

            public string? TimestampRaw { get; }
        }

        /// <summary>Keeps the code from the candidate that got furthest, so the trace names the most specific failure in any order.</summary>
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
        #endregion
    }
}
