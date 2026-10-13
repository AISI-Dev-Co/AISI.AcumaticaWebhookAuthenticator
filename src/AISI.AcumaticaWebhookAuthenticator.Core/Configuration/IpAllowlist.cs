// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace AISI.AcumaticaWebhookAuthenticator.Configuration
{
    /// <summary>IP addresses and CIDR blocks a client address is checked against, where IPv4-mapped IPv6 matches the corresponding IPv4 entry.</summary>
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
        /// <summary>Parses addresses (<c>203.0.113.7</c>, <c>2001:db8::1</c>) and CIDR blocks (<c>203.0.113.0/24</c>, <c>2001:db8::/32</c>).</summary>
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

        /// <summary>Parses a comma-separated list as stored by the editing screen, skipping blank entries.</summary>
        public static IpAllowlist ParseCsv(string entries)
        {
            if (entries is null)
            {
                throw new ArgumentNullException(nameof(entries));
            }

            var nonBlank = new List<string>();

            foreach (string entry in entries.Split(','))
            {
                string trimmed = entry.Trim();
                if (trimmed.Length > 0)
                {
                    nonBlank.Add(trimmed);
                }
            }

            return Parse(nonBlank.ToArray());
        }
        #endregion

        #region Matching
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

            foreach (Entry entry in _entries)
            {
                if (entry.Matches(address.AddressFamily, candidate))
                {
                    return true;
                }
            }

            return false;
        }

        public override string ToString() => _description;
        #endregion

        #region Internals
        /// <summary>Parses one address or CIDR block into a network with its host bits cleared.</summary>
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

            if (!TryParseAddress(addressPart, out IPAddress address))
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

            if (effectivePrefix > maxPrefix)
            {
                throw new FormatException(
                    FormattableString.Invariant(
                        $"'{text}' has prefix length {effectivePrefix}; {address.AddressFamily} allows 0 to {maxPrefix}."));
            }

            // 203.0.113.7/24 behaves as 203.0.113.0/24, the conventional reading.
            ZeroHostBits(network, effectivePrefix);

            return new Entry(address.AddressFamily, network, effectivePrefix);
        }

        /// <summary>Parses an IPv6 address, or an IPv4 address written strictly as four dotted-decimal octets.</summary>
        private static bool TryParseAddress(string text, out IPAddress address)
        {
            if (text.IndexOf(':') >= 0)
            {
                return IPAddress.TryParse(text, out address);
            }

            // Not IPAddress.TryParse: it takes shorthand ("10" is 0.0.0.10) and octal, so "10/8" would become 0.0.0.0/8.
            address = IPAddress.None;
            string[] parts = text.Split('.');
            if (parts.Length != 4)
            {
                return false;
            }

            var octets = new byte[4];

            for (int i = 0; i < octets.Length; i++)
            {
                string part = parts[i];
                bool leadingZero = part.Length > 1 && part[0] == '0';

                if (part.Length == 0 || part.Length > 3 || leadingZero ||
                    !byte.TryParse(part, NumberStyles.None, CultureInfo.InvariantCulture, out octets[i]))
                {
                    return false;
                }
            }

            address = new IPAddress(octets);
            return true;
        }

        /// <summary>Clears every bit of the address beyond the prefix length.</summary>
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
