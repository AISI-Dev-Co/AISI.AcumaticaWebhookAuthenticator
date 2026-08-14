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
    /// <para>
    /// This type only answers "is this address in the set". Where the address comes from is the
    /// harder problem — the platform exposes no remote address, so the only source is a forwarded
    /// header, and a forwarded header is only evidence when a trusted proxy controls it. That
    /// caveat lives on <see cref="Authentication.IpAllowlistAuthenticator"/>, which is the type
    /// that reads one.
    /// </para>
    /// <para>
    /// An IPv4-mapped IPv6 address (<c>::ffff:203.0.113.7</c>) matches IPv4 entries: dual-stack
    /// front ends report IPv4 callers that way, and treating the two spellings as different
    /// addresses would make an allowlist work or fail depending on the proxy's stack. Otherwise
    /// families never cross-match.
    /// </para>
    /// <para>
    /// Instances are immutable and safe to share across threads.
    /// </para>
    /// </remarks>
    public sealed class IpAllowlist
    {
        private readonly IReadOnlyList<Entry> _entries;
        private readonly string _description;

        private IpAllowlist(IReadOnlyList<Entry> entries, string description)
        {
            _entries = entries;
            _description = description;
        }

        /// <summary>
        /// Parses allowlist entries: bare addresses (<c>203.0.113.7</c>, <c>2001:db8::1</c>) and
        /// CIDR blocks (<c>203.0.113.0/24</c>, <c>2001:db8::/32</c>).
        /// </summary>
        /// <param name="entries">The entries. At least one is required.</param>
        /// <returns>The allowlist.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="entries"/> is null.</exception>
        /// <exception cref="ArgumentException">
        /// <paramref name="entries"/> is empty. An empty allowlist denies every request; if that is
        /// really the intent, it deserves to be written somewhere more legible than an empty list.
        /// </exception>
        /// <exception cref="FormatException">
        /// An entry is not an address or CIDR block. Parse time rather than request time, for the
        /// same reason <see cref="Signing.SignedPayloadTemplate.Parse"/> throws: a bad entry is a
        /// configuration error and should surface at construction, not as every request from the
        /// mistyped network denying in production.
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
        /// Whether <paramref name="address"/> falls inside any entry.
        /// </summary>
        /// <param name="address">The address to test. Null is never contained.</param>
        /// <returns><see langword="true"/> when the address is allowed.</returns>
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

            // Every entry is evaluated. Nothing here is secret, but the habit of not
            // short-circuiting over request-controlled comparisons is cheaper to keep than to
            // reason about per call site.
            foreach (Entry entry in _entries)
            {
                contained |= entry.Matches(address.AddressFamily, candidate);
            }

            return contained;
        }

        /// <summary>The entries as parsed, for configuration screens and traces.</summary>
        /// <returns>The entry list, comma-separated.</returns>
        public override string ToString() => _description;

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

            // Host bits beyond the prefix are zeroed so that 203.0.113.7/24 behaves as
            // 203.0.113.0/24 — the conventional reading — instead of silently matching nothing
            // past the first full byte.
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
    }
}
