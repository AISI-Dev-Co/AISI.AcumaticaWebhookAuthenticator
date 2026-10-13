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

        public bool Success { get; }

        // For a bare {body} template this is the request buffer itself, so treat it as read-only.
        public byte[] Bytes { get; }

        // The body is decoded lossily as UTF-8 for humans, so never sign this.
        public string Preview { get; }

        public string FailureCode { get; }

        internal static TemplateResolution Succeeded(byte[] bytes, string preview) =>
            new TemplateResolution(true, bytes, preview, string.Empty);

        internal static TemplateResolution Failed(string failureCode) =>
            new TemplateResolution(false, Array.Empty<byte>(), string.Empty, failureCode);
    }
}
