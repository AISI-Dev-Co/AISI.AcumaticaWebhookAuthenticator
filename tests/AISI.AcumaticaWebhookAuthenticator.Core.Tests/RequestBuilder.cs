// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Text;
using AISI.AcumaticaWebhookAuthenticator.Authentication;

namespace AISI.AcumaticaWebhookAuthenticator.Tests
{
    /// <summary>
    /// Builds <see cref="WebhookAuthContext"/> instances for tests.
    /// </summary>
    internal sealed class RequestBuilder
    {
        private readonly Dictionary<string, string> _headers = new(StringComparer.OrdinalIgnoreCase);
        private byte[] _body = Array.Empty<byte>();
        private string? _method = "POST";
        private string? _path = "/api/webhooks/company/inbound";
        private DateTimeOffset _receivedOn = DateTimeOffset.UnixEpoch;

        public static RequestBuilder Post() => new();

        public RequestBuilder WithBody(string body)
        {
            _body = Encoding.UTF8.GetBytes(body);
            return this;
        }

        public RequestBuilder WithBodyBytes(byte[] body)
        {
            _body = body;
            return this;
        }

        public RequestBuilder WithHeader(string name, string value)
        {
            _headers[name] = value;
            return this;
        }

        public RequestBuilder WithoutMethod()
        {
            _method = null;
            return this;
        }

        public RequestBuilder WithoutPath()
        {
            _path = null;
            return this;
        }

        public RequestBuilder WithMethod(string method)
        {
            _method = method;
            return this;
        }

        public RequestBuilder WithPath(string path)
        {
            _path = path;
            return this;
        }

        public RequestBuilder ReceivedAt(DateTimeOffset receivedOn)
        {
            _receivedOn = receivedOn;
            return this;
        }

        public RequestBuilder ReceivedAtUnixSeconds(long seconds)
        {
            _receivedOn = DateTimeOffset.FromUnixTimeSeconds(seconds);
            return this;
        }

        public WebhookAuthContext Build() =>
            new(_body, _headers, _method, _path, _receivedOn);
    }
}
