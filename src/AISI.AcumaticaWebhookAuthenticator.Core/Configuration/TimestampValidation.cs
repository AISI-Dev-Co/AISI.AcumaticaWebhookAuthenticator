// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Globalization;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Diagnostics;

namespace AISI.AcumaticaWebhookAuthenticator.Configuration
{
    /// <summary>
    /// Where the signed timestamp comes from and how wide the replay window is.
    /// </summary>
    /// <remarks>
    /// The timestamp is only meaningful when it is <em>inside the signed payload</em>. Validating a
    /// timestamp the signature does not cover achieves nothing, because an attacker replaying a
    /// captured request can rewrite it freely. <see cref="Authentication.HmacAuthenticator"/>
    /// enforces the pairing at construction: configuring this without a <c>{timestamp}</c> token in
    /// the template is rejected outright.
    /// </remarks>
    public sealed class TimestampValidation
    {
        private readonly string? _headerName;
        private readonly SignatureExtraction? _signatureHeaderElement;

        private TimestampValidation(
            string? headerName,
            SignatureExtraction? signatureHeaderElement,
            TimestampFormat format,
            TimeSpan tolerance)
        {
            if (tolerance < TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(tolerance),
                    tolerance,
                    "The replay tolerance cannot be negative; a negative window rejects every request.");
            }

            _headerName = headerName;
            _signatureHeaderElement = signatureHeaderElement;
            Format = format;
            Tolerance = tolerance;
        }

        /// <summary>Wire format of the timestamp.</summary>
        public TimestampFormat Format { get; }

        /// <summary>
        /// Whether the timestamp is read out of the signature header itself rather than a header of
        /// its own. When it is, the timestamp belongs to <em>one</em> signature header value — so on
        /// a request whose signature header arrived more than once, each value's signatures must be
        /// verified against the payload built from that value's own timestamp, not the first one's.
        /// </summary>
        public bool ReadsFromSignatureHeader => _signatureHeaderElement is object;

        /// <summary>How far from the receipt time a request may be, in either direction.</summary>
        public TimeSpan Tolerance { get; }

        /// <summary>
        /// The timestamp is carried in its own header.
        /// </summary>
        /// <param name="headerName">Header name.</param>
        /// <param name="tolerance">Replay window either side of receipt. Must not be negative.</param>
        /// <param name="format">Wire format. Defaults to Unix seconds.</param>
        /// <returns>The validation configuration.</returns>
        /// <exception cref="ArgumentException"><paramref name="headerName"/> is null or blank.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="tolerance"/> is negative.</exception>
        public static TimestampValidation FromHeader(
            string headerName,
            TimeSpan tolerance,
            TimestampFormat format = TimestampFormat.UnixSeconds)
        {
            if (string.IsNullOrWhiteSpace(headerName))
            {
                throw new ArgumentException("A header name is required.", nameof(headerName));
            }

            return new TimestampValidation(headerName, null, format, tolerance);
        }

        /// <summary>
        /// The timestamp is an element inside the signature header itself, as with Stripe's
        /// <c>t=</c>.
        /// </summary>
        /// <param name="elementKey">Element name within the signature header.</param>
        /// <param name="tolerance">Replay window either side of receipt. Must not be negative.</param>
        /// <param name="format">Wire format. Defaults to Unix seconds.</param>
        /// <param name="pairSeparator">Separator between elements. Defaults to ','.</param>
        /// <param name="keyValueSeparator">Separator between an element's name and value. Defaults to '='.</param>
        /// <returns>The validation configuration.</returns>
        /// <exception cref="ArgumentException"><paramref name="elementKey"/> is null or blank.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="tolerance"/> is negative.</exception>
        public static TimestampValidation FromSignatureHeaderElement(
            string elementKey,
            TimeSpan tolerance,
            TimestampFormat format = TimestampFormat.UnixSeconds,
            char pairSeparator = ',',
            char keyValueSeparator = '=')
        {
            // The separators are bound here rather than borrowed from the signature extraction at
            // read time. An earlier revision passed them in and then ignored them, which meant a
            // sender using anything other than ',' and '=' silently lost its timestamp.
            SignatureExtraction element = SignatureExtraction.KeyValueElement(
                elementKey,
                pairSeparator,
                keyValueSeparator);

            return new TimestampValidation(null, element, format, tolerance);
        }

        /// <summary>
        /// Reads the raw timestamp text for this configuration.
        /// </summary>
        /// <param name="context">The request.</param>
        /// <param name="signatureHeaderValues">
        /// The signature header's values, needed when the timestamp lives inside it.
        /// </param>
        /// <returns>The raw text, or <see langword="null"/> when absent.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="context"/> is null.</exception>
        public string? ReadRaw(WebhookAuthContext context, IReadOnlyList<string>? signatureHeaderValues)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (_headerName is object)
            {
                return context.TryGetHeader(_headerName, out string value) ? value : null;
            }

            IReadOnlyList<string> elements = _signatureHeaderElement!.Extract(signatureHeaderValues);
            return elements.Count > 0 ? elements[0] : null;
        }

        /// <summary>
        /// Checks a raw timestamp against the replay window.
        /// </summary>
        /// <param name="raw">The raw timestamp text, exactly as sent.</param>
        /// <param name="receivedOn">When the request arrived.</param>
        /// <returns>Success, or a failure carrying an <see cref="AuthFailureCode"/>.</returns>
        public AuthResult Validate(string? raw, DateTimeOffset receivedOn)
        {
            if (string.IsNullOrWhiteSpace(raw))
            {
                return AuthResult.Fail(AuthFailureCode.TimestampMissing);
            }

            if (!TryParse(raw!, out DateTimeOffset sentOn))
            {
                return AuthResult.Fail(AuthFailureCode.TimestampMalformed);
            }

            TimeSpan drift = receivedOn - sentOn;

            // Checked in both directions. A request stamped in the future is not a curiosity to be
            // waved through: it is either a badly skewed sender or an attacker buying replay headroom.
            if (drift > Tolerance || drift < -Tolerance)
            {
                return AuthResult.Fail(AuthFailureCode.TimestampOutsideTolerance);
            }

            return AuthResult.Success();
        }

        private bool TryParse(string raw, out DateTimeOffset value)
        {
            value = default;
            string trimmed = raw.Trim();

            switch (Format)
            {
                case TimestampFormat.UnixSeconds:
                    if (!long.TryParse(trimmed, NumberStyles.Integer, CultureInfo.InvariantCulture, out long seconds))
                    {
                        return false;
                    }

                    try
                    {
                        value = DateTimeOffset.FromUnixTimeSeconds(seconds);
                        return true;
                    }
                    catch (ArgumentOutOfRangeException)
                    {
                        return false;
                    }

                case TimestampFormat.UnixMilliseconds:
                    if (!long.TryParse(trimmed, NumberStyles.Integer, CultureInfo.InvariantCulture, out long milliseconds))
                    {
                        return false;
                    }

                    try
                    {
                        value = DateTimeOffset.FromUnixTimeMilliseconds(milliseconds);
                        return true;
                    }
                    catch (ArgumentOutOfRangeException)
                    {
                        return false;
                    }

                case TimestampFormat.Iso8601:
                    return DateTimeOffset.TryParse(
                        trimmed,
                        CultureInfo.InvariantCulture,
                        DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                        out value);

                default:
                    return false;
            }
        }
    }
}
