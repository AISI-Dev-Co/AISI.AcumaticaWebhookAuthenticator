// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using AISI.AcumaticaWebhookAuthenticator.Acumatica.DAC;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using PX.Data;

namespace AISI.AcumaticaWebhookAuthenticator.Acumatica
{
    /// <summary>ERP-backed secrets and IP policy for one webhook, cached 30s per tenant.</summary>
    public sealed class ErpSecretProvider : IWebhookSecretProvider, IAuthenticatorRefiner
    {
        #region Construction and state
        /// <summary>How long a read (including a miss) is reused before the database is consulted again.</summary>
        public static readonly TimeSpan CacheDuration = TimeSpan.FromSeconds(30);

        private static readonly ConcurrentDictionary<(string Company, Guid WebhookId), Lazy<CacheEntry>> Cache =
            new ConcurrentDictionary<(string Company, Guid WebhookId), Lazy<CacheEntry>>();

        private readonly Guid _webhookId;

        /// <summary>
        /// Creates a provider for one webhook registration.
        /// </summary>
        /// <param name="webhookId">The registration's <c>WebHook.WebHookID</c>.</param>
        public ErpSecretProvider(Guid webhookId)
        {
            _webhookId = webhookId;
        }
        #endregion

        #region Secrets and policy
        /// <inheritdoc/>
        public WebhookSecret? GetSecret() => Current().Secret;

        /// <summary>
        /// Applies the row's IP allowlist, when one is configured, around <paramref name="inner"/>;
        /// substitutes a deny-everything authenticator when the stored configuration cannot be
        /// applied.
        /// </summary>
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
                // The administrator asked for an IP restriction; the one thing this must not do
                // is quietly not restrict.
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

            // Whichever thread wins the swap loads once; losers read the winner's value. The
            // replacement is returned even if a slow load leaves it nominally stale already -
            // it is the freshest value there is, and re-looping on it would spin.
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
                // ExecutionAndPublication memoizes the exception; left in place it would replay
                // one transient database failure on every request until the app restarted. Evict
                // (only if this exact lazy is still the entry) so the next request retries.
                ((ICollection<KeyValuePair<(string, Guid), Lazy<CacheEntry>>>)Cache)
                    .Remove(new KeyValuePair<(string, Guid), Lazy<CacheEntry>>(key, lazy));
                throw;
            }
        }

        private Lazy<CacheEntry> CreateEntry((string Company, Guid WebhookId) key) =>
            new Lazy<CacheEntry>(Load, LazyThreadSafetyMode.ExecutionAndPublication);

        private CacheEntry Load()
        {
            var graph = PXGraph.CreateInstance<PXGraph>();
            PXCache cache = graph.Caches[typeof(AISIWebhookSecret)];

            PXDBCryptStringAttribute.SetDecrypted<AISIWebhookSecret.secret>(cache, true);
            PXDBCryptStringAttribute.SetDecrypted<AISIWebhookSecret.rotatingSecret>(cache, true);

            AISIWebhookSecret? row = PXSelectReadonly<
                    AISIWebhookSecret,
                    Where<AISIWebhookSecret.webHookID, Equal<Required<AISIWebhookSecret.webHookID>>>>
                .Select(graph, _webhookId);

            // Stamped after the query, not before it: a slow query stamped early would produce an
            // entry already near expiry, and a refresh that immediately re-refreshes.
            DateTime fetchedOn = DateTime.UtcNow;

            if (row is null)
            {
                return new CacheEntry(null, null, null, IpAllowlistAuthenticator.DefaultTrustedProxyDepth, false, fetchedOn);
            }

            WebhookSecret? secret = null;

            if (!string.IsNullOrEmpty(row.Secret))
            {
                secret = WebhookSecret.FromUtf8(row.Secret!);

                if (!string.IsNullOrEmpty(row.RotatingSecret) && row.RotatingExpiresOn is object)
                {
                    secret = secret.WithRotatingUtf8(
                        row.RotatingSecret!,
                        new DateTimeOffset(DateTime.SpecifyKind(row.RotatingExpiresOn.Value, DateTimeKind.Utc)));
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
                // The database can be edited past the screen's validation; unparseable fails
                // closed, not open.
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

        #region Internals
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

        /// <summary>
        /// Denies every request; substituted when a stored allowlist cannot be applied. Carries
        /// the wrapped scheme's challenge so the deny-all state is indistinguishable from any
        /// other 401.
        /// </summary>
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
