// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;

namespace AISI.AcumaticaWebhookAuthenticator.Diagnostics
{
    /// <summary>
    /// The outcome of resolving a signed-payload template against a request.
    /// </summary>
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

        /// <summary>
        /// The exact bytes to sign. Empty when <see cref="Success"/> is <see langword="false"/>.
        /// For a template that is exactly <c>{body}</c> this aliases the request body buffer rather
        /// than copying it — treat it as read-only.
        /// </summary>
        public byte[] Bytes { get; }

        /// <summary>
        /// A human-readable rendering of the signed payload, for diagnosis. The body is decoded as
        /// UTF-8, which may be lossy; never sign this.
        /// </summary>
        public string Preview { get; }

        /// <summary>
        /// An <see cref="AuthFailureCode"/> when resolution failed, otherwise empty.
        /// </summary>
        public string FailureCode { get; }

        /// <summary>Creates a successful resolution.</summary>
        /// <param name="bytes">The resolved bytes.</param>
        /// <param name="preview">Human-readable rendering.</param>
        /// <returns>The resolution.</returns>
        public static TemplateResolution Succeeded(byte[] bytes, string preview) =>
            new TemplateResolution(true, bytes, preview, string.Empty);

        /// <summary>Creates a failed resolution.</summary>
        /// <param name="failureCode">An <see cref="AuthFailureCode"/> value.</param>
        /// <returns>The resolution.</returns>
        public static TemplateResolution Failed(string failureCode) =>
            new TemplateResolution(false, Array.Empty<byte>(), string.Empty, failureCode);
    }
}
