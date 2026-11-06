using Microsoft.Win32.SafeHandles;

namespace Core.Analysis;

/// <summary>
/// Read-only, thread-safe access to a PE file through a single OS handle.
/// All parsers share one instance so the file is opened exactly once per scan.
/// </summary>
public sealed class PeFileReader : IDisposable
{
    private readonly SafeFileHandle _handle;

    private PeFileReader(SafeFileHandle handle, long length)
    {
        _handle = handle;
        Length = length;
    }

    public long Length { get; }

    public static PeFileReader Open(string filePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

        SafeFileHandle handle = File.OpenHandle(
            filePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read);

        try
        {
            return new PeFileReader(handle, RandomAccess.GetLength(handle));
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    public bool IsRangeWithinFile(long offset, long length) =>
        offset >= 0 && length >= 0 && offset <= Length && length <= Length - offset;

    public int Read(long offset, Span<byte> destination)
    {
        EnsureRange(offset, destination.Length);
        return RandomAccess.Read(_handle, destination, offset);
    }

    public void ReadExactly(long offset, Span<byte> destination, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        EnsureRange(offset, destination.Length);

        int totalRead = 0;
        while (totalRead < destination.Length)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int read = RandomAccess.Read(_handle, destination[totalRead..], offset + totalRead);
            if (read == 0)
            {
                throw new EndOfStreamException("A PE structure extends past the end of the file.");
            }

            totalRead += read;
        }
    }

    public async ValueTask ReadExactlyAsync(
        long offset,
        Memory<byte> destination,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        EnsureRange(offset, destination.Length);

        int totalRead = 0;
        while (totalRead < destination.Length)
        {
            int read = await RandomAccess.ReadAsync(
                _handle,
                destination[totalRead..],
                offset + totalRead,
                cancellationToken).ConfigureAwait(false);

            if (read == 0)
            {
                throw new EndOfStreamException("A PE structure extends past the end of the file.");
            }

            totalRead += read;
        }
    }

    private void EnsureRange(long offset, long length)
    {
        if (!IsRangeWithinFile(offset, length))
        {
            throw new EndOfStreamException("A PE structure extends past the end of the file.");
        }
    }

    public void Dispose() => _handle.Dispose();
}
