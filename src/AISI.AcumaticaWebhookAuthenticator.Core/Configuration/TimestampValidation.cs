// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Globalization;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using AISI.AcumaticaWebhookAuthenticator.Diagnostics;

namespace AISI.AcumaticaWebhookAuthenticator.Configuration
{
    /// <summary>Where the signed timestamp comes from and how wide the replay window is.</summary>
    public sealed class TimestampValidation
    {
        #region Construction and state
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

            if (!Enum.IsDefined(typeof(TimestampFormat), format))
            {
                throw new ArgumentOutOfRangeException(nameof(format), format, "Unknown timestamp format.");
            }

            _headerName = headerName;
            _signatureHeaderElement = signatureHeaderElement;
            Format = format;
            Tolerance = tolerance;
        }

        public TimestampFormat Format { get; }

        // An element of the signature header belongs to one header value, so it is read per value rather than per request.
        public bool ReadsFromSignatureHeader => _signatureHeaderElement is object;

        public TimeSpan Tolerance { get; }
        #endregion

        #region Factories
        /// <summary>The timestamp is carried in its own header.</summary>
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

        /// <summary>The timestamp is an element inside the signature header itself, as with Stripe's <c>t=</c>.</summary>
        public static TimestampValidation FromSignatureHeaderElement(
            string elementKey,
            TimeSpan tolerance,
            TimestampFormat format = TimestampFormat.UnixSeconds,
            char pairSeparator = ',',
            char keyValueSeparator = '=')
        {
            SignatureExtraction element = SignatureExtraction.KeyValueElement(
                elementKey,
                pairSeparator,
                keyValueSeparator);

            return new TimestampValidation(null, element, format, tolerance);
        }
        #endregion

        #region Reading and validation
        /// <summary>Reads the raw timestamp text from its header or from the given signature header values, or null when absent.</summary>
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

        /// <summary>Checks a raw timestamp against the replay window around the receipt time.</summary>
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

            // Both directions: a future timestamp buys an attacker replay headroom.
            if (drift > Tolerance || drift < -Tolerance)
            {
                return AuthResult.Fail(AuthFailureCode.TimestampOutsideTolerance);
            }

            return AuthResult.Success();
        }
        #endregion

        #region Internals
        /// <summary>Parses raw timestamp text in the configured <see cref="Format"/>.</summary>
        private bool TryParse(string raw, out DateTimeOffset value)
        {
            value = default;
            string trimmed = raw.Trim();

            if (Format == TimestampFormat.Iso8601)
            {
                return DateTimeOffset.TryParse(
                    trimmed,
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                    out value);
            }

            if (!long.TryParse(trimmed, NumberStyles.Integer, CultureInfo.InvariantCulture, out long number))
            {
                return false;
            }

            try
            {
                value = Format == TimestampFormat.UnixSeconds
                    ? DateTimeOffset.FromUnixTimeSeconds(number)
                    : DateTimeOffset.FromUnixTimeMilliseconds(number);
                return true;
            }
            catch (ArgumentOutOfRangeException)
            {
                return false;
            }
        }
        #endregion
    }
}
