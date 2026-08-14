// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Concurrent;
using AISI.AcumaticaWebhookAuthenticator.Acumatica.DAC;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using PX.Data;

namespace AISI.AcumaticaWebhookAuthenticator.Acumatica
{
    /// <summary>
    /// Reads a webhook's authentication configuration — secret, rotation pair, IP allowlist —
    /// from its <see cref="AISIWebhookSecret"/> row, maintained on screen AS301000.
    /// </summary>
    /// <remarks>
    /// Rows are read through a <see cref="PXCache"/> with the crypt fields set decrypted. Reads
    /// (misses included) are cached for <see cref="CacheDuration"/> in a store shared across
    /// instances, so admin edits apply within a minute with no restart and unconfigured endpoints
    /// cost no query per request; entries are <see cref="Lazy{T}"/> so an expiry under load
    /// refreshes with one database read. Thread-safe.
    /// </remarks>
    public sealed class ErpSecretProvider : IWebhookSecretProvider, IAuthenticatorRefiner
    {
        /// <summary>How long a read (including a miss) is reused before the database is consulted again.</summary>
        public static readonly TimeSpan CacheDuration = TimeSpan.FromSeconds(30);

        private static readonly ConcurrentDictionary<Guid, Lazy<CacheEntry>> Cache =
            new ConcurrentDictionary<Guid, Lazy<CacheEntry>>();

        private readonly Guid _webhookId;

        /// <summary>
        /// Creates a provider for one webhook registration.
        /// </summary>
        /// <param name="webhookId">The registration's <c>WebHook.WebHookID</c>.</param>
        public ErpSecretProvider(Guid webhookId)
        {
            _webhookId = webhookId;
        }

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
                return DenyAllAuthenticator.Instance;
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

        private CacheEntry Current()
        {
            while (true)
            {
                Lazy<CacheEntry> lazy = Cache.GetOrAdd(_webhookId, CreateEntry);
                CacheEntry entry = lazy.Value;

                if (DateTime.UtcNow - entry.FetchedOn < CacheDuration)
                {
                    return entry;
                }

                // Whichever thread wins the swap loads once; losers re-read the winner's value.
                Cache.TryUpdate(_webhookId, CreateEntry(_webhookId), lazy);
            }
        }

        private Lazy<CacheEntry> CreateEntry(Guid webhookId) =>
            new Lazy<CacheEntry>(Load, System.Threading.LazyThreadSafetyMode.ExecutionAndPublication);

        private CacheEntry Load()
        {
            DateTime fetchedOn = DateTime.UtcNow;

            var graph = PXGraph.CreateInstance<PXGraph>();
            PXCache cache = graph.Caches[typeof(AISIWebhookSecret)];

            PXDBCryptStringAttribute.SetDecrypted<AISIWebhookSecret.secret>(cache, true);
            PXDBCryptStringAttribute.SetDecrypted<AISIWebhookSecret.rotatingSecret>(cache, true);

            AISIWebhookSecret? row = PXSelectReadonly<
                    AISIWebhookSecret,
                    Where<AISIWebhookSecret.webHookID, Equal<Required<AISIWebhookSecret.webHookID>>>>
                .Select(graph, _webhookId);

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

        /// <summary>Denies every request; substituted when a stored allowlist cannot be applied.</summary>
        private sealed class DenyAllAuthenticator : IWebhookAuthenticator
        {
            public static DenyAllAuthenticator Instance { get; } = new DenyAllAuthenticator();

            public string Code => "MISCONFIGURED";

            public AuthResult Authenticate(WebhookAuthContext context) =>
                AuthResult.Fail(Diagnostics.AuthFailureCode.Misconfigured);
        }
    }
}
