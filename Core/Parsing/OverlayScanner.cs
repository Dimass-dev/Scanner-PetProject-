using Core.Analysis;
using Core.Utils;
using Core.Models;

namespace Core.Parsing;

/// <summary>
/// Scans for overlay data (extra bytes after the last PE section).
/// </summary>
public sealed class OverlayScanner
{
    private const int ChunkSize = 65536;
    private const long MaxEntropyBytes = 100 * 1024 * 1024;

    /// <summary>Scan for overlay data after sections.</summary>
    public OverlayInfo Scan(
        string filePath,
        IReadOnlyList<SingleSectionInfo> sections,
        HPInfo? header = null,
        CancellationToken cancellationToken = default)
    {
        using var reader = PeFileReader.Open(filePath);
        return Scan(reader, sections, header, cancellationToken);
    }

    public OverlayInfo Scan(
        PeFileReader reader,
        IReadOnlyList<SingleSectionInfo> sections,
        HPInfo? header = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(sections);

        long fileSize = reader.Length;

        if (sections.Count == 0)
        {
            return new OverlayInfo(0, 0, 0.0);
        }

        // Find the end of the last section
        long maxSectionEnd = 0;
        foreach (var section in sections)
        {
            cancellationToken.ThrowIfCancellationRequested();
            long sectionEnd = (long)section.PointerToRawData + section.SizeOfRawData;
            if (sectionEnd > maxSectionEnd)
            {
                maxSectionEnd = sectionEnd;
            }
        }

        // If binary has an Authenticode signature at or after the last section,
        // it is legitimate certificate data, not malicious overlay data.
        if (header != null && header.SecurityDirectoryFileOffset > 0 && header.SecurityDirectorySize > 0)
        {
            long certOffset = header.SecurityDirectoryFileOffset;
            long certSize = header.SecurityDirectorySize;
            if (certOffset <= long.MaxValue - certSize)
            {
                long certEnd = certOffset + certSize;
                if (certOffset >= maxSectionEnd)
                {
                    maxSectionEnd = Math.Max(maxSectionEnd, certEnd);
                }
            }
        }

        long overlaySize = fileSize - maxSectionEnd;
        if (overlaySize <= 0)
        {
            return new OverlayInfo(maxSectionEnd, 0, 0.0);
        }

        // Calculate entropy of overlay in chunks without allocating large buffers
        double entropy = 0.0;
        if (overlaySize < MaxEntropyBytes)
        {
            Span<long> frequency = stackalloc long[256];
            frequency.Clear();

            byte[] buffer = new byte[ChunkSize];
            long bytesRemaining = overlaySize;
            long overlayOffset = maxSectionEnd;

            while (bytesRemaining > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();

                int toRead = (int)Math.Min(buffer.Length, bytesRemaining);
                int bytesRead = reader.Read(
                    overlayOffset + (overlaySize - bytesRemaining),
                    buffer.AsSpan(0, toRead));

                if (bytesRead == 0)
                {
                    break;
                }

                for (int i = 0; i < bytesRead; i++)
                {
                    frequency[buffer[i]]++;
                }

                bytesRemaining -= bytesRead;
            }

            entropy = ShannonEntropy.FromFrequencies(frequency, overlaySize - bytesRemaining);
        }

        return new OverlayInfo(maxSectionEnd, overlaySize, entropy);
    }

}
