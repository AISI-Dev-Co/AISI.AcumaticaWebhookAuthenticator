// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using AISI.AcumaticaWebhookAuthenticator.Acumatica.DAC;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using PX.Data;
using PX.Data.BQL;
using PX.Data.BQL.Fluent;

namespace AISI.AcumaticaWebhookAuthenticator.Acumatica
{
    /// <summary>
    /// Reads a webhook's secret, rotation pair and IP allowlist from its <see cref="AISIWebhookSecret"/>
    /// row (screen AS301000), cached for <see cref="CacheDuration"/>. Thread-safe.
    /// </summary>
    /// <remarks>The cache is keyed by tenant as well as webhook: tenants copied from one another share <c>WebHookID</c>s.</remarks>
    public sealed class ErpSecretProvider : IWebhookSecretProvider, IAuthenticatorRefiner
    {
        #region Construction and state
        /// <summary>How long a read (including a miss) is reused before the database is consulted again.</summary>
        public static readonly TimeSpan CacheDuration = TimeSpan.FromSeconds(30);

        private static readonly ConcurrentDictionary<(string Company, Guid WebhookId), Lazy<CacheEntry>> Cache =
            new ConcurrentDictionary<(string Company, Guid WebhookId), Lazy<CacheEntry>>();

        private readonly Guid _webhookId;

        /// <summary>Creates a provider for one webhook registration.</summary>
        /// <param name="webhookId">The registration's <c>WebHook.WebHookID</c>.</param>
        public ErpSecretProvider(Guid webhookId)
        {
            _webhookId = webhookId;
        }
        #endregion

        #region Secrets and policy
        /// <inheritdoc/>
        public WebhookSecret? GetSecret() => Current().Secret;

        /// <summary>Wraps <paramref name="inner"/> in the row's IP allowlist, or denies everything if the stored one is unusable.</summary>
        /// <param name="inner">The authenticator for this webhook.</param>
        /// <exception cref="ArgumentNullException"><paramref name="inner"/> is null.</exception>
        public IWebhookAuthenticator Refine(IWebhookAuthenticator inner)
        {
            if (inner is null)
            {
                throw new ArgumentNullException(nameof(inner));
            }

            CacheEntry entry = Current();

            if (entry.AllowlistBroken)
            {
                // An IP restriction was asked for; never quietly fall back to none.
                return new DenyAllAuthenticator(inner);
            }

            if (entry.Allowlist is null)
            {
                return inner;
            }

            return new IpAllowlistAuthenticator(
                inner,
                entry.Allowlist,
                entry.ClientAddressHeader,
                entry.TrustedProxyDepth);
        }
        #endregion

        #region Cache and loading
        private CacheEntry Current()
        {
            (string, Guid) key = (PXAccess.GetCompanyName(), _webhookId);

            Lazy<CacheEntry> lazy = Cache.GetOrAdd(key, CreateEntry);
            CacheEntry entry = Value(key, lazy);

            if (DateTime.UtcNow - entry.FetchedOn < CacheDuration)
            {
                return entry;
            }

            // The swap's winner loads once and losers share its value, returned even if stale rather than spinning.
            Lazy<CacheEntry> replacement = CreateEntry(key);
            if (!Cache.TryUpdate(key, replacement, lazy))
            {
                replacement = Cache.GetOrAdd(key, replacement);
            }

            return Value(key, replacement);
        }

        private static CacheEntry Value((string, Guid) key, Lazy<CacheEntry> lazy)
        {
            try
            {
                return lazy.Value;
            }
            catch
            {
                // Evict this exact entry so a transient database failure is retried, not memoised until restart.
                ((ICollection<KeyValuePair<(string, Guid), Lazy<CacheEntry>>>)Cache)
                    .Remove(new KeyValuePair<(string, Guid), Lazy<CacheEntry>>(key, lazy));
                throw;
            }
        }

        private Lazy<CacheEntry> CreateEntry((string Company, Guid WebhookId) key) =>
            new Lazy<CacheEntry>(Load, LazyThreadSafetyMode.ExecutionAndPublication);

        /// <summary>Reads a webhook's row with the crypt fields decrypted. Never display the result.</summary>
        internal static AISIWebhookSecret? SelectDecrypted(Guid webhookId)
        {
            var graph = PXGraph.CreateInstance<PXGraph>();
            PXCache cache = graph.Caches[typeof(AISIWebhookSecret)];

            PXDBCryptStringAttribute.SetDecrypted<AISIWebhookSecret.secret>(cache, true);
            PXDBCryptStringAttribute.SetDecrypted<AISIWebhookSecret.rotatingSecret>(cache, true);

            return SelectFrom<AISIWebhookSecret>
                .Where<AISIWebhookSecret.webHookID.IsEqual<@P.AsGuid>>
                .View.ReadOnly.Select(graph, webhookId);
        }

        private CacheEntry Load()
        {
            AISIWebhookSecret? row = SelectDecrypted(_webhookId);

            // Stamped after the query so a slow read does not produce an entry already near expiry.
            DateTime fetchedOn = DateTime.UtcNow;

            if (row is null)
            {
                return new CacheEntry(null, null, null, IpAllowlistAuthenticator.DefaultTrustedProxyDepth, false, fetchedOn);
            }

            WebhookSecret? secret = null;

            if (!string.IsNullOrEmpty(row.Secret))
            {
                try
                {
                    SecretEncoding encoding = SecretEncodingListAttribute.ToEncoding(row.SecretEncoding);
                    secret = WebhookSecret.Parse(row.Secret!, encoding);

                    if (!string.IsNullOrEmpty(row.RotatingSecret) && row.RotatingExpiresOn is object)
                    {
                        secret = secret.WithRotating(
                            row.RotatingSecret!,
                            encoding,
                            new DateTimeOffset(DateTime.SpecifyKind(row.RotatingExpiresOn.Value, DateTimeKind.Utc)));
                    }
                }
                catch (FormatException failure)
                {
                    secret = null;
                    PXTrace.WriteError(
                        "Webhook {0}: the stored secret could not be decoded and all requests will be denied until it is fixed on the webhook secrets screen. {1}",
                        _webhookId,
                        failure.Message);
                }
            }

            IpAllowlist? allowlist = null;
            bool allowlistBroken = false;
            string header = string.IsNullOrWhiteSpace(row.ClientAddressHeader)
                ? IpAllowlistAuthenticator.DefaultClientAddressHeader
                : row.ClientAddressHeader!.Trim();
            int depth = row.TrustedProxyDepth is int value && value >= 1
                ? value
                : IpAllowlistAuthenticator.DefaultTrustedProxyDepth;

            if (!string.IsNullOrWhiteSpace(row.AllowedAddresses))
            {
                // The database can be edited past the screen's validation; unparseable fails closed.
                try
                {
                    allowlist = IpAllowlist.ParseCsv(row.AllowedAddresses!);
                }
                catch (Exception failure) when (failure is FormatException || failure is ArgumentException)
                {
                    allowlistBroken = true;
                    PXTrace.WriteError(
                        "Webhook {0}: the stored IP allowlist could not be parsed and all requests will be denied until it is fixed on the webhook secrets screen. {1}",
                        _webhookId,
                        failure.Message);
                }
            }

            return new CacheEntry(secret, allowlist, header, depth, allowlistBroken, fetchedOn);
        }
        #endregion

        #region Nested types
        private sealed class CacheEntry
        {
            public CacheEntry(
                WebhookSecret? secret,
                IpAllowlist? allowlist,
                string? clientAddressHeader,
                int trustedProxyDepth,
                bool allowlistBroken,
                DateTime fetchedOn)
            {
                Secret = secret;
                Allowlist = allowlist;
                ClientAddressHeader = clientAddressHeader ?? IpAllowlistAuthenticator.DefaultClientAddressHeader;
                TrustedProxyDepth = trustedProxyDepth;
                AllowlistBroken = allowlistBroken;
                FetchedOn = fetchedOn;
            }

            public WebhookSecret? Secret { get; }

            public IpAllowlist? Allowlist { get; }

            public string ClientAddressHeader { get; }

            public int TrustedProxyDepth { get; }

            public bool AllowlistBroken { get; }

            public DateTime FetchedOn { get; }
        }

        /// <summary>Denies every request, with the wrapped scheme's challenge so it looks like any other 401.</summary>
        private sealed class DenyAllAuthenticator : IWebhookAuthenticator, IChallengeSource
        {
            private readonly IWebhookAuthenticator _inner;

            public DenyAllAuthenticator(IWebhookAuthenticator inner)
            {
                _inner = inner;
            }

            public string Code => "MISCONFIGURED";

            public string? Challenge => (_inner as IChallengeSource)?.Challenge;

            public AuthResult Authenticate(WebhookAuthContext context) =>
                AuthResult.Fail(Diagnostics.AuthFailureCode.Misconfigured);
        }
        #endregion
    }
}
