// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace AISI.AcumaticaWebhookAuthenticator.Configuration
{
    /// <summary>
    /// A set of IP addresses and CIDR blocks that senders are allowed to call from.
    /// </summary>
    /// <remarks>
    /// Only answers "is this address in the set"; where the address comes from — and why that is
    /// the harder problem — lives on <see cref="Authentication.IpAllowlistAuthenticator"/>.
    /// IPv4-mapped IPv6 (<c>::ffff:203.0.113.7</c>) matches IPv4 entries, because dual-stack front
    /// ends report IPv4 callers that way; otherwise families never cross-match. Immutable and safe
    /// to share across threads.
    /// </remarks>
    public sealed class IpAllowlist
    {
        #region Construction and state
        private readonly IReadOnlyList<Entry> _entries;
        private readonly string _description;

        private IpAllowlist(IReadOnlyList<Entry> entries, string description)
        {
            _entries = entries;
            _description = description;
        }
        #endregion

        #region Parsing
        /// <summary>
        /// Parses allowlist entries: bare addresses (<c>203.0.113.7</c>, <c>2001:db8::1</c>) and
        /// CIDR blocks (<c>203.0.113.0/24</c>, <c>2001:db8::/32</c>).
        /// </summary>
        /// <param name="entries">The entries. At least one is required.</param>
        /// <exception cref="ArgumentNullException"><paramref name="entries"/> is null.</exception>
        /// <exception cref="ArgumentException"><paramref name="entries"/> is empty — an empty allowlist would deny every request.</exception>
        /// <exception cref="FormatException">
        /// An entry is not an address or CIDR block. Thrown at parse time so a configuration error
        /// surfaces at construction, not as every request denying in production.
        /// </exception>
        public static IpAllowlist Parse(params string[] entries)
        {
            if (entries is null)
            {
                throw new ArgumentNullException(nameof(entries));
            }

            if (entries.Length == 0)
            {
                throw new ArgumentException(
                    "An allowlist needs at least one entry; an empty one would deny every request.",
                    nameof(entries));
            }

            var parsed = new List<Entry>(entries.Length);

            foreach (string entry in entries)
            {
                parsed.Add(ParseEntry(entry));
            }

            return new IpAllowlist(parsed, string.Join(", ", entries));
        }

        /// <summary>
        /// Parses a comma-separated list — the one tokenization both the editing screen and the
        /// request path call, so what the screen accepts is what runs.
        /// </summary>
        /// <param name="entries">Comma-separated entries, e.g. <c>203.0.113.0/24, 2001:db8::/32</c>.</param>
        /// <exception cref="ArgumentNullException"><paramref name="entries"/> is null.</exception>
        /// <exception cref="ArgumentException"><paramref name="entries"/> contains no entries.</exception>
        /// <exception cref="FormatException">An entry is not an address or CIDR block.</exception>
        public static IpAllowlist ParseCsv(string entries)
        {
            if (entries is null)
            {
                throw new ArgumentNullException(nameof(entries));
            }

            return Parse(entries.Split(CsvSeparators, StringSplitOptions.RemoveEmptyEntries));
        }

        private static readonly char[] CsvSeparators = { ',' };
        #endregion

        #region Matching
        /// <summary>
        /// Whether <paramref name="address"/> falls inside any entry.
        /// </summary>
        /// <param name="address">The address to test. Null is never contained.</param>
        public bool Contains(IPAddress? address)
        {
            if (address is null)
            {
                return false;
            }

            if (address.IsIPv4MappedToIPv6)
            {
                address = address.MapToIPv4();
            }

            byte[] candidate = address.GetAddressBytes();
            bool contained = false;

            // Not short-circuited: the discipline is cheaper to keep than to reason about per
            // call site.
            foreach (Entry entry in _entries)
            {
                contained |= entry.Matches(address.AddressFamily, candidate);
            }

            return contained;
        }

        /// <summary>The entries as written, for configuration screens and traces.</summary>
        public override string ToString() => _description;
        #endregion

        #region Internals
        private static Entry ParseEntry(string? entry)
        {
            if (string.IsNullOrWhiteSpace(entry))
            {
                throw new FormatException("An allowlist entry cannot be blank.");
            }

            string text = entry!.Trim();
            string addressPart = text;
            int? prefixLength = null;

            int slash = text.IndexOf('/');
            if (slash >= 0)
            {
                addressPart = text.Substring(0, slash);
                string prefixPart = text.Substring(slash + 1);

                if (!int.TryParse(prefixPart, NumberStyles.None, CultureInfo.InvariantCulture, out int prefix))
                {
                    throw new FormatException(
                        FormattableString.Invariant($"'{text}' has a malformed prefix length."));
                }

                prefixLength = prefix;
            }

            if (!IPAddress.TryParse(addressPart, out IPAddress address))
            {
                throw new FormatException(
                    FormattableString.Invariant($"'{text}' is not an IP address or CIDR block."));
            }

            if (address.IsIPv4MappedToIPv6)
            {
                address = address.MapToIPv4();
            }

            byte[] network = address.GetAddressBytes();
            int maxPrefix = network.Length * 8;
            int effectivePrefix = prefixLength ?? maxPrefix;

            if (effectivePrefix < 0 || effectivePrefix > maxPrefix)
            {
                throw new FormatException(
                    FormattableString.Invariant(
                        $"'{text}' has prefix length {effectivePrefix}; {address.AddressFamily} allows 0 to {maxPrefix}."));
            }

            // 203.0.113.7/24 behaves as 203.0.113.0/24 — the conventional reading.
            ZeroHostBits(network, effectivePrefix);

            return new Entry(address.AddressFamily, network, effectivePrefix);
        }

        private static void ZeroHostBits(byte[] network, int prefixLength)
        {
            int fullBytes = prefixLength / 8;
            int remainderBits = prefixLength % 8;

            if (remainderBits > 0)
            {
                network[fullBytes] &= (byte)(0xFF << (8 - remainderBits));
                fullBytes++;
            }

            for (int i = fullBytes; i < network.Length; i++)
            {
                network[i] = 0;
            }
        }

        private readonly struct Entry
        {
            private readonly AddressFamily _family;
            private readonly byte[] _network;
            private readonly int _prefixLength;

            public Entry(AddressFamily family, byte[] network, int prefixLength)
            {
                _family = family;
                _network = network;
                _prefixLength = prefixLength;
            }

            public bool Matches(AddressFamily candidateFamily, byte[] candidate)
            {
                if (candidateFamily != _family || candidate.Length != _network.Length)
                {
                    return false;
                }

                int fullBytes = _prefixLength / 8;
                int remainderBits = _prefixLength % 8;

                for (int i = 0; i < fullBytes; i++)
                {
                    if (candidate[i] != _network[i])
                    {
                        return false;
                    }
                }

                if (remainderBits > 0)
                {
                    byte mask = (byte)(0xFF << (8 - remainderBits));
                    if ((candidate[fullBytes] & mask) != _network[fullBytes])
                    {
                        return false;
                    }
                }

                return true;
            }
        }
        #endregion
    }
}
