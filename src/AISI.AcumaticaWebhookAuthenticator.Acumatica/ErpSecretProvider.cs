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
    /// Reads a webhook's authentication configuration from the ERP database — the
    /// <see cref="AISIWebhookSecret"/> row keyed by the webhook registration, maintained on the
    /// webhook secrets screen (AS301000): the secret, its rotation pair, and the optional IP
    /// allowlist.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Rows are read through a <see cref="PXCache"/> with the crypt fields set decrypted, which is
    /// what makes <c>[PXRSACryptString]</c> yield plaintext to the verifier while the database
    /// holds ciphertext.
    /// </para>
    /// <para>
    /// Reads are cached for <see cref="CacheDuration"/> in a store shared across instances, so a
    /// per-request handler instance still amortises them. The cache is short enough that an
    /// administrator's edit — a new secret, a changed allowlist — takes effect within a minute
    /// without an application restart, and the negative result is cached too, so a flood of
    /// requests against an unconfigured endpoint does not become a query per request. Entries are
    /// <see cref="Lazy{T}"/> so an expiry under load refreshes with exactly one database read
    /// instead of one per in-flight request. Thread-safe.
    /// </para>
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
        /// Applies the row's IP allowlist, when the administrator configured one, around
        /// <paramref name="inner"/>.
        /// </summary>
        /// <param name="inner">The authenticator for this webhook.</param>
        /// <returns>
        /// <paramref name="inner"/> unchanged when no allowlist is configured; an
        /// <see cref="IpAllowlistAuthenticator"/> over it when one is; a deny-everything
        /// authenticator when the stored configuration cannot be applied. Called per request so an
        /// edit takes effect on the cache cadence — which is exactly why the allowlist is not
        /// baked into the authenticator at construction.
        /// </returns>
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
                // The row carries an allowlist that cannot be applied (edited outside the screen's
                // validation). The administrator asked for an IP restriction; the one thing this
                // must not do is quietly not restrict.
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

                // Swap the stale entry for a fresh Lazy; whichever thread wins the swap loads
                // once, and every loser re-reads the winner's value on the next pass.
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
                // The screen validates on save, but the database can be edited past it. A stored
                // allowlist that cannot be parsed fails closed rather than open.
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

        /// <summary>
        /// Denies every request. Substituted when a stored allowlist cannot be applied, because an
        /// IP restriction the administrator asked for must not quietly stop restricting.
        /// </summary>
        private sealed class DenyAllAuthenticator : IWebhookAuthenticator
        {
            public static DenyAllAuthenticator Instance { get; } = new DenyAllAuthenticator();

            public string Code => "MISCONFIGURED";

            public AuthResult Authenticate(WebhookAuthContext context) =>
                AuthResult.Fail(Diagnostics.AuthFailureCode.Misconfigured);
        }
    }
}
