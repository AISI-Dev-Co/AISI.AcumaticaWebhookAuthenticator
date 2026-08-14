// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.IO;
using System.Threading.Tasks;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using Xunit;

namespace AISI.AcumaticaWebhookAuthenticator.Tests
{
    public class BoundedBodyReaderTests
    {
        [Fact]
        public void BodyUnderTheCap_IsReadCompletely()
        {
            byte[] body = Bytes(1000);

            BoundedBodyRead result = BoundedBodyReader.Read(NonSeekable(body), maxLength: 2000);

            Assert.True(result.WithinLimit);
            Assert.Equal(body, result.Body);
        }

        [Fact]
        public void BodyExactlyAtTheCap_IsAccepted()
        {
            byte[] body = Bytes(2000);

            BoundedBodyRead result = BoundedBodyReader.Read(NonSeekable(body), maxLength: 2000);

            Assert.True(result.WithinLimit);
            Assert.Equal(body, result.Body);
        }

        [Fact]
        public void BodyOverTheCap_IsRejectedWithNothingRetained()
        {
            BoundedBodyRead result = BoundedBodyReader.Read(NonSeekable(Bytes(2001)), maxLength: 2000);

            Assert.False(result.WithinLimit);
            Assert.Empty(result.Body);
        }

        [Fact]
        public void BodyMuchLargerThanOneChunk_IsRejectedWithoutBuffering()
        {
            // 100k against a 2k cap: the reject must come from the running count, not from
            // accumulating everything first.
            BoundedBodyRead result = BoundedBodyReader.Read(NonSeekable(Bytes(100_000)), maxLength: 2000);

            Assert.False(result.WithinLimit);
        }

        [Fact]
        public void DeclaredLengthOverTheCap_RejectsWithoutReading()
        {
            var source = new CountingStream(NonSeekable(Bytes(10)));

            BoundedBodyRead result = BoundedBodyReader.Read(source, maxLength: 2000, declaredLength: 5000);

            Assert.False(result.WithinLimit);
            Assert.Equal(0, source.ReadCalls);
        }

        [Fact]
        public void UnderdeclaredLength_DoesNotTruncateTheActualBody()
        {
            // A sender that declares 10 bytes and sends 1500 still gets the whole body read (the
            // declared value is a capacity hint, not a limit) — and still gets capped by maxLength.
            byte[] body = Bytes(1500);

            BoundedBodyRead result = BoundedBodyReader.Read(NonSeekable(body), maxLength: 2000, declaredLength: 10);

            Assert.True(result.WithinLimit);
            Assert.Equal(body, result.Body);
        }

        [Fact]
        public void LyingDeclaredLength_DoesNotBypassTheCap()
        {
            BoundedBodyRead result = BoundedBodyReader.Read(NonSeekable(Bytes(3000)), maxLength: 2000, declaredLength: 10);

            Assert.False(result.WithinLimit);
        }

        [Fact]
        public void NegativeDeclaredLength_IsIgnoredRatherThanThrowing()
        {
            byte[] body = Bytes(100);

            BoundedBodyRead result = BoundedBodyReader.Read(NonSeekable(body), maxLength: 2000, declaredLength: -1);

            Assert.True(result.WithinLimit);
            Assert.Equal(body, result.Body);
        }

        [Fact]
        public void EmptyBody_ReadsAsEmpty()
        {
            BoundedBodyRead result = BoundedBodyReader.Read(NonSeekable(Array.Empty<byte>()));

            Assert.True(result.WithinLimit);
            Assert.Empty(result.Body);
        }

        [Fact]
        public async Task AsyncPath_BehavesLikeTheSyncPath()
        {
            byte[] body = Bytes(1500);

            BoundedBodyRead ok = await BoundedBodyReader.ReadAsync(NonSeekable(body), maxLength: 2000);
            BoundedBodyRead over = await BoundedBodyReader.ReadAsync(NonSeekable(Bytes(2001)), maxLength: 2000);

            Assert.True(ok.WithinLimit);
            Assert.Equal(body, ok.Body);
            Assert.False(over.WithinLimit);
        }

        [Fact]
        public void NullStream_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => BoundedBodyReader.Read(null!));
        }

        [Fact]
        public void NegativeCap_Throws()
        {
            Assert.Throws<ArgumentOutOfRangeException>(
                () => BoundedBodyReader.Read(NonSeekable(Bytes(1)), maxLength: -1));
        }

        private static byte[] Bytes(int count)
        {
            var bytes = new byte[count];
            for (int i = 0; i < count; i++)
            {
                bytes[i] = (byte)(i % 251);
            }

            return bytes;
        }

        /// <summary>
        /// Wraps the body so the reader sees what a chunked-transfer request stream looks like: no
        /// Length, no Seek, and reads that return fewer bytes than asked for.
        /// </summary>
        private static DribbleStream NonSeekable(byte[] body) => new(body);

        private sealed class DribbleStream : Stream
        {
            private readonly byte[] _data;
            private int _position;

            public DribbleStream(byte[] data) => _data = data;

            public override bool CanRead => true;

            public override bool CanSeek => false;

            public override bool CanWrite => false;

            public override long Length => throw new NotSupportedException();

            public override long Position
            {
                get => throw new NotSupportedException();
                set => throw new NotSupportedException();
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                // At most 700 bytes per call, a size that never aligns with the reader's chunk.
                int toCopy = Math.Min(Math.Min(count, 700), _data.Length - _position);
                Array.Copy(_data, _position, buffer, offset, toCopy);
                _position += toCopy;
                return toCopy;
            }

            public override void Flush()
            {
            }

            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

            public override void SetLength(long value) => throw new NotSupportedException();

            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        }

        private sealed class CountingStream : Stream
        {
            private readonly Stream _inner;

            public CountingStream(Stream inner) => _inner = inner;

            public int ReadCalls { get; private set; }

            public override bool CanRead => true;

            public override bool CanSeek => false;

            public override bool CanWrite => false;

            public override long Length => throw new NotSupportedException();

            public override long Position
            {
                get => throw new NotSupportedException();
                set => throw new NotSupportedException();
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                ReadCalls++;
                return _inner.Read(buffer, offset, count);
            }

            public override void Flush()
            {
            }

            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

            public override void SetLength(long value) => throw new NotSupportedException();

            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        }
    }
}
