// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;

namespace AISI.AcumaticaWebhookAuthenticator.Diagnostics
{
    /// <summary>The outcome of resolving a signed-payload template against a request.</summary>
    public sealed class TemplateResolution
    {
        private TemplateResolution(bool success, byte[] bytes, string preview, string failureCode)
        {
            Success = success;
            Bytes = bytes;
            Preview = preview;
            FailureCode = failureCode;
        }

        /// <summary>Whether the template resolved.</summary>
        public bool Success { get; }

        /// <summary>The exact bytes to sign; empty on failure. For a bare <c>{body}</c> template this is the request buffer itself, so treat it as read-only.</summary>
        public byte[] Bytes { get; }

        /// <summary>A human-readable rendering of the signed payload, with the body decoded lossily as UTF-8. Never sign this.</summary>
        public string Preview { get; }

        /// <summary>An <see cref="AuthFailureCode"/> when resolution failed, otherwise empty.</summary>
        public string FailureCode { get; }

        internal static TemplateResolution Succeeded(byte[] bytes, string preview) =>
            new TemplateResolution(true, bytes, preview, string.Empty);

        internal static TemplateResolution Failed(string failureCode) =>
            new TemplateResolution(false, Array.Empty<byte>(), string.Empty, failureCode);
    }
}
