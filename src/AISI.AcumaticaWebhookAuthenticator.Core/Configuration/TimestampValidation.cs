// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Globalization;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Diagnostics;

namespace AISI.AcumaticaWebhookAuthenticator.Configuration
{
    /// <summary>
    /// Wire format of a signed timestamp.
    /// </summary>
    public enum TimestampFormat
    {
        /// <summary>Seconds since the Unix epoch. Stripe and most others.</summary>
        UnixSeconds = 0,

        /// <summary>Milliseconds since the Unix epoch.</summary>
        UnixMilliseconds = 1,

        /// <summary>An ISO 8601 / RFC 3339 instant.</summary>
        Iso8601 = 2,
    }

    /// <summary>
    /// Where the signed timestamp comes from and how wide the replay window is.
    /// </summary>
    /// <remarks>
    /// The timestamp is only meaningful when it is <em>inside the signed payload</em>. Validating a
    /// timestamp that the signature does not cover achieves nothing, because an attacker replaying a
    /// captured request can rewrite it freely.
    /// </remarks>
    public sealed class TimestampValidation
    {
        private readonly string _source;
        private readonly bool _fromSignatureHeader;

        private TimestampValidation(string source, bool fromSignatureHeader, TimestampFormat format, TimeSpan tolerance)
        {
            _source = source;
            _fromSignatureHeader = fromSignatureHeader;
            Format = format;
            Tolerance = tolerance;
        }

        /// <summary>Wire format of the timestamp.</summary>
        public TimestampFormat Format { get; }

        /// <summary>
        /// How far from the receipt time a request may be, in either direction.
        /// </summary>
        public TimeSpan Tolerance { get; }

        /// <summary>
        /// The timestamp is carried in its own header.
        /// </summary>
        /// <param name="headerName">Header name.</param>
        /// <param name="tolerance">Replay window either side of receipt.</param>
        /// <param name="format">Wire format. Defaults to Unix seconds.</param>
        /// <returns>The validation configuration.</returns>
        /// <exception cref="ArgumentException"><paramref name="headerName"/> is null or blank.</exception>
        public static TimestampValidation FromHeader(
            string headerName,
            TimeSpan tolerance,
            TimestampFormat format = TimestampFormat.UnixSeconds)
        {
            if (string.IsNullOrWhiteSpace(headerName))
            {
                throw new ArgumentException("A header name is required.", nameof(headerName));
            }

            return new TimestampValidation(headerName, false, format, tolerance);
        }

        /// <summary>
        /// The timestamp is an element inside the signature header itself, as with Stripe's
        /// <c>t=</c>.
        /// </summary>
        /// <param name="elementKey">Element name within the signature header.</param>
        /// <param name="tolerance">Replay window either side of receipt.</param>
        /// <param name="format">Wire format. Defaults to Unix seconds.</param>
        /// <returns>The validation configuration.</returns>
        /// <exception cref="ArgumentException"><paramref name="elementKey"/> is null or blank.</exception>
        public static TimestampValidation FromSignatureHeaderElement(
            string elementKey,
            TimeSpan tolerance,
            TimestampFormat format = TimestampFormat.UnixSeconds)
        {
            if (string.IsNullOrWhiteSpace(elementKey))
            {
                throw new ArgumentException("An element key is required.", nameof(elementKey));
            }

            return new TimestampValidation(elementKey, true, format, tolerance);
        }

        /// <summary>
        /// Reads the raw timestamp text for this configuration.
        /// </summary>
        /// <param name="context">The request.</param>
        /// <param name="signatureHeaderValue">The signature header value, needed when the timestamp lives inside it.</param>
        /// <param name="separators">Separators to use when reading an element out of the signature header.</param>
        /// <returns>The raw text, or <see langword="null"/> when absent.</returns>
        public string? ReadRaw(WebhookAuthContext context, string? signatureHeaderValue, SignatureExtraction separators)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (separators is null)
            {
                throw new ArgumentNullException(nameof(separators));
            }

            if (!_fromSignatureHeader)
            {
                return context.TryGetHeader(_source, out string value) ? value : null;
            }

            foreach (string candidate in SignatureExtraction
                .KeyValueElement(_source)
                .Extract(signatureHeaderValue))
            {
                return candidate;
            }

            return null;
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
