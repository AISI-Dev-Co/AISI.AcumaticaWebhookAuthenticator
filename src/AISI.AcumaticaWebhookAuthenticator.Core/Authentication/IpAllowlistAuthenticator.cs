// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Net;
using AISI.AcumaticaWebhookAuthenticator.Configuration;
using AISI.AcumaticaWebhookAuthenticator.Diagnostics;

namespace AISI.AcumaticaWebhookAuthenticator.Authentication
{
    /// <summary>
    /// Restricts another authenticator to callers on an <see cref="IpAllowlist"/>, read from a
    /// forwarded header.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <strong>This is only as trustworthy as the header, and the header is only trustworthy
    /// behind a proxy you control.</strong> Acumatica's <c>WebhookRequest</c> exposes no remote
    /// address, so the caller's IP can only come from something like <c>X-Forwarded-For</c> — a
    /// header any sender can write. Deploy this when, and only when, a trusted front proxy (IIS
    /// ARR, a load balancer, a CDN) overwrites or appends to that header on every request; without
    /// one, an attacker states whatever address the allowlist wants to hear, and the gate is
    /// theatre. This is defence in depth on top of a signature scheme, or a last resort for a
    /// sender that signs nothing — it is not authentication.
    /// </para>
    /// <para>
    /// Proxies <em>append</em>: <c>X-Forwarded-For: attacker-supplied, …, added-by-your-proxy</c>.
    /// Only the last <see cref="TrustedProxyDepth"/> entries were written by infrastructure you
    /// trust, so the client address is taken from that depth exactly — counted from the right,
    /// never the left, which is the sender's to invent. One trusted proxy (depth 1) reads the
    /// rightmost entry; a chain of two (say, CDN then load balancer) reads the second from the
    /// right.
    /// </para>
    /// <para>
    /// Fails closed: header absent, entry unparseable, or fewer entries than the depth requires
    /// all deny. The failure codes are diagnostic only — the response to the sender is the same
    /// uniform 401 as every other failure.
    /// </para>
    /// <para>
    /// The allowlist check runs before the inner authenticator, so a disallowed caller costs no
    /// signature work. Instances are immutable and safe to share across threads.
    /// </para>
    /// </remarks>
    public sealed class IpAllowlistAuthenticator : IWebhookAuthenticator
    {
        private readonly IpAllowlist _allowlist;
        private readonly string _clientAddressHeader;

        /// <summary>
        /// Creates the gate.
        /// </summary>
        /// <param name="inner">The authenticator that runs for allowed callers.</param>
        /// <param name="allowlist">The allowed addresses and blocks.</param>
        /// <param name="clientAddressHeader">
        /// The header the trusted proxy records the caller's address in. Defaults to
        /// <c>X-Forwarded-For</c>.
        /// </param>
        /// <param name="trustedProxyDepth">
        /// How many trailing entries of the header were appended by trusted infrastructure. The
        /// client address is the entry at exactly this depth from the right. Defaults to 1 — a
        /// single trusted proxy.
        /// </param>
        /// <exception cref="ArgumentNullException"><paramref name="inner"/> or <paramref name="allowlist"/> is null.</exception>
        /// <exception cref="ArgumentException"><paramref name="clientAddressHeader"/> is null or blank.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="trustedProxyDepth"/> is less than 1.</exception>
        public IpAllowlistAuthenticator(
            IWebhookAuthenticator inner,
            IpAllowlist allowlist,
            string clientAddressHeader = "X-Forwarded-For",
            int trustedProxyDepth = 1)
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

        /// <summary>
        /// The authenticator that runs for allowed callers. Exposed so a host can see through the
        /// gate — the Acumatica adapter unwraps it to find a <see cref="BasicAuthenticator"/>
        /// challenge and to vet an <see cref="HmacAuthenticator"/> template.
        /// </summary>
        public IWebhookAuthenticator Inner { get; }

        /// <summary>How many trailing header entries are trusted; the client is read at this depth.</summary>
        public int TrustedProxyDepth { get; }

        /// <summary>
        /// The inner scheme's code with an <c>+IP</c> suffix, so a trace shows the gate is in
        /// force rather than silently narrowing a scheme that reads as unrestricted.
        /// </summary>
        public string Code => Inner.Code + "+IP";

        /// <inheritdoc/>
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

        private bool TryReadClientAddress(IReadOnlyList<string> headerValues, out IPAddress? address)
        {
            address = null;

            // A header sent as several lines is equivalent to one comma-joined line; flattening in
            // arrival order preserves the append semantics the depth count relies on.
            var entries = new List<string>();

            foreach (string headerValue in headerValues)
            {
                foreach (string part in headerValue.Split(','))
                {
                    entries.Add(part.Trim());
                }
            }

            if (entries.Count < TrustedProxyDepth)
            {
                // Fewer entries than trusted proxies means the proxy chain this configuration
                // describes did not handle the request. Whatever is in the header, none of it is
                // evidence.
                return false;
            }

            string candidate = entries[entries.Count - TrustedProxyDepth];
            return TryParseAddress(candidate, out address);
        }

        private static bool TryParseAddress(string text, out IPAddress? address)
        {
            address = null;

            if (text.Length == 0)
            {
                return false;
            }

            // Bracketed IPv6, with or without a port: [2001:db8::1] or [2001:db8::1]:4711.
            if (text[0] == '[')
            {
                int close = text.IndexOf(']');
                if (close < 0)
                {
                    return false;
                }

                text = text.Substring(1, close - 1);
                return IPAddress.TryParse(text, out address);
            }

            if (IPAddress.TryParse(text, out address))
            {
                return true;
            }

            // Some front ends (IIS ARR among them) append IPv4 with a port. A lone colon cannot
            // be part of an IPv4 literal, so stripping from the last one is unambiguous; bare
            // IPv6 with a port is not distinguishable from an address and is required to use
            // brackets instead.
            int lastColon = text.LastIndexOf(':');
            if (lastColon > 0 && text.IndexOf(':') == lastColon)
            {
                return IPAddress.TryParse(text.Substring(0, lastColon), out address);
            }

            return false;
        }
    }
}
