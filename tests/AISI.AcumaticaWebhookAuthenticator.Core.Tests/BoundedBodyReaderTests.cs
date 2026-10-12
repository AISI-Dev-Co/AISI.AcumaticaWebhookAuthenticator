// Copyright (c) 2026 AISI Dev Co. Licensed under the MIT License.

using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AISI.AcumaticaWebhookAuthenticator.Authentication;
using Xunit;

namespace AISI.AcumaticaWebhookAuthenticator.Tests
{
    public class BoundedBodyReaderTests
    {
        private const int Cap = 2000;

        [Theory]
        [InlineData(Cap - 1000, true)]
        [InlineData(Cap, true)]
        [InlineData(Cap + 1, false)]
        public async Task Body_IsReadOnlyWhenWithinTheCap(int length, bool withinLimit)
        {
            byte[] body = Bytes(length);

            BoundedBodyRead result = await BoundedBodyReader.ReadAsync(new DribbleStream(body), maxLength: Cap);

            Assert.Equal(withinLimit, result.WithinLimit);
            Assert.Equal(withinLimit ? body : Array.Empty<byte>(), result.Body);
        }

        [Fact]
        public async Task DeclaredLengthOverTheCap_RejectsWithoutReading()
        {
            var source = new DribbleStream(Bytes(10));

            BoundedBodyRead result = await BoundedBodyReader.ReadAsync(source, maxLength: Cap, declaredLength: Cap + 1);

            Assert.False(result.WithinLimit);
            Assert.Equal(0, source.ReadCalls);
        }

        [Fact]
        public void DeclaredLength_DoesNotPreallocateTheWholeCap()
        {
            var source = new DribbleStream(Bytes(10));

            long before = GC.GetAllocatedBytesForCurrentThread();
            Task<BoundedBodyRead> read = BoundedBodyReader.ReadAsync(source, declaredLength: BoundedBodyReader.DefaultMaxLength);
            long allocated = GC.GetAllocatedBytesForCurrentThread() - before;

            Assert.True(read.IsCompletedSuccessfully);
            Assert.True(allocated < BoundedBodyReader.MaxInitialCapacity * 2, $"{allocated} bytes allocated");
        }

        [Fact]
        public async Task UnderdeclaredLength_DoesNotTruncateTheActualBody()
        {
            byte[] body = Bytes(1500);

            BoundedBodyRead result = await BoundedBodyReader.ReadAsync(new DribbleStream(body), maxLength: Cap, declaredLength: 10);

            Assert.True(result.WithinLimit);
            Assert.Equal(body, result.Body);
        }

        [Fact]
        public async Task LyingDeclaredLength_DoesNotBypassTheCap()
        {
            BoundedBodyRead result = await BoundedBodyReader.ReadAsync(new DribbleStream(Bytes(Cap + 1000)), maxLength: Cap, declaredLength: 10);

            Assert.False(result.WithinLimit);
        }

        [Fact]
        public async Task NegativeDeclaredLength_IsIgnoredRatherThanThrowing()
        {
            byte[] body = Bytes(100);

            BoundedBodyRead result = await BoundedBodyReader.ReadAsync(new DribbleStream(body), maxLength: Cap, declaredLength: -1);

            Assert.True(result.WithinLimit);
            Assert.Equal(body, result.Body);
        }

        [Fact]
        public async Task EmptyBody_ReadsAsEmpty()
        {
            BoundedBodyRead result = await BoundedBodyReader.ReadAsync(new DribbleStream(Array.Empty<byte>()));

            Assert.True(result.WithinLimit);
            Assert.Empty(result.Body);
        }

        [Fact]
        public async Task NegativeCap_Throws()
        {
            await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
                () => BoundedBodyReader.ReadAsync(new DribbleStream(Bytes(1)), maxLength: -1));
        }

        [Fact]
        public void CompleteWithNullBody_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => BoundedBodyRead.Complete(null!));
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

        /// <summary>A chunked-transfer-like stream: no Length, no Seek, short reads, synchronous completion.</summary>
        private sealed class DribbleStream : Stream
        {
            // Never aligns with the reader's chunk size.
            private const int MaxReadSize = 700;

            private readonly byte[] _data;
            private int _position;

            public DribbleStream(byte[] data) => _data = data;

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

            public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

            public override int Read(Span<byte> buffer)
            {
                ReadCalls++;
                int toCopy = Math.Min(Math.Min(buffer.Length, MaxReadSize), _data.Length - _position);
                _data.AsSpan(_position, toCopy).CopyTo(buffer);
                _position += toCopy;
                return toCopy;
            }

            public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
                Task.FromResult(Read(buffer, offset, count));

            public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
                new(Read(buffer.Span));

            public override void Flush()
            {
            }

            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

            public override void SetLength(long value) => throw new NotSupportedException();

            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        }
    }
}
