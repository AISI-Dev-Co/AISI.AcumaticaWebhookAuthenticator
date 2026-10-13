// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Net;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using AISI.AcumaticaWebhookAuthenticator.Diagnostics;

namespace AISI.AcumaticaWebhookAuthenticator.Authentication
{
    /// <summary>Restricts another authenticator to an IP allowlist read from a forwarded header at the trusted proxy depth, so it is meaningful only behind a proxy you control.</summary>
    public sealed class IpAllowlistAuthenticator : IWebhookAuthenticator, IChallengeSource, IRequestPathDependent
    {
        #region Construction and state
        public const string DefaultClientAddressHeader = "X-Forwarded-For";

        public const int DefaultTrustedProxyDepth = 1;

        private readonly IpAllowlist _allowlist;
        private readonly string _clientAddressHeader;

        public IpAllowlistAuthenticator(
            IWebhookAuthenticator inner,
            IpAllowlist allowlist,
            string clientAddressHeader = DefaultClientAddressHeader,
            int trustedProxyDepth = DefaultTrustedProxyDepth)
        {
            if (string.IsNullOrWhiteSpace(clientAddressHeader))
            {
                throw new ArgumentException("A client-address header name is required.", nameof(clientAddressHeader));
            }

            if (trustedProxyDepth < 1)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(trustedProxyDepth),
                    trustedProxyDepth,
                    "At least one trusted proxy must have written the header; with none, no entry is evidence and the gate cannot work at all.");
            }

            Inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _allowlist = allowlist ?? throw new ArgumentNullException(nameof(allowlist));
            _clientAddressHeader = clientAddressHeader;
            TrustedProxyDepth = trustedProxyDepth;
        }
        #endregion

        #region Properties and capabilities
        public IWebhookAuthenticator Inner { get; }

        public int TrustedProxyDepth { get; }

        public string Code => Inner.Code + "+IP";

        public string? Challenge => (Inner as IChallengeSource)?.Challenge;

        public bool RequiresRequestPath => (Inner as IRequestPathDependent)?.RequiresRequestPath ?? false;
        #endregion

        #region Authentication
        public AuthResult Authenticate(WebhookAuthContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (!context.TryGetHeaderValues(_clientAddressHeader, out IReadOnlyList<string> headerValues))
            {
                return AuthResult.Fail(AuthFailureCode.ClientAddressMissing);
            }

            if (!TryReadClientAddress(headerValues, out IPAddress? address))
            {
                return AuthResult.Fail(AuthFailureCode.ClientAddressMalformed);
            }

            if (!_allowlist.Contains(address))
            {
                return AuthResult.Fail(AuthFailureCode.ClientAddressDenied);
            }

            return Inner.Authenticate(context);
        }
        #endregion

        #region Address parsing
        /// <summary>Reads the client address from the header entry at the trusted proxy depth, counted from the right.</summary>
        private bool TryReadClientAddress(IReadOnlyList<string> headerValues, out IPAddress? address)
        {
            // Repeated header lines are equivalent to one comma-joined line; walk its entries right to left.
            int remaining = TrustedProxyDepth;
            for (int line = headerValues.Count - 1; line >= 0; line--)
            {
                string value = headerValues[line];
                int end = value.Length;
                while (true)
                {
                    int comma = end == 0 ? -1 : value.LastIndexOf(',', end - 1);
                    if (--remaining == 0)
                    {
                        return TryParseAddress(value.Substring(comma + 1, end - comma - 1).Trim(), out address);
                    }

                    if (comma < 0)
                    {
                        break;
                    }

                    end = comma;
                }
            }

            // Fewer entries than trusted proxies: the configured chain did not handle this request.
            address = null;
            return false;
        }

        /// <summary>Parses one forwarded entry as a bare address, a bracketed IPv6 address with optional port, or an IPv4 address with a port.</summary>
        private static bool TryParseAddress(string text, out IPAddress? address)
        {
            address = null;

            if (text.Length == 0)
            {
                return false;
            }

            // [v6] or [v6]:port; anything else after the bracket fails the whole entry.
            if (text[0] == '[')
            {
                int close = text.IndexOf(']');
                if (close < 0 || !IsAbsentOrPort(text, close + 1))
                {
                    return false;
                }

                return IPAddress.TryParse(text.Substring(1, close - 1), out address);
            }

            if (IPAddress.TryParse(text, out address))
            {
                return true;
            }

            // IPv4 with a port (IIS ARR): a single colon is unambiguous, as IPv6 with a port must be bracketed.
            int lastColon = text.LastIndexOf(':');
            if (lastColon > 0 && text.IndexOf(':') == lastColon && IsPort(text, lastColon + 1))
            {
                return IPAddress.TryParse(text.Substring(0, lastColon), out address);
            }

            return false;
        }

        private static bool IsAbsentOrPort(string text, int index) =>
            index == text.Length || (text[index] == ':' && IsPort(text, index + 1));

        private static bool IsPort(string text, int index)
        {
            if (index >= text.Length)
            {
                return false;
            }

            for (int i = index; i < text.Length; i++)
            {
                if (text[i] < '0' || text[i] > '9')
                {
                    return false;
                }
            }

            return true;
        }
        #endregion
    }
}
