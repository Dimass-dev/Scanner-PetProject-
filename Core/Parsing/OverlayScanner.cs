using Core.Analysis;
using Core.Models;

namespace Core.Parsing;

/// <summary>
/// Scans for overlay data (extra bytes after the last PE section).
/// </summary>
public sealed class OverlayScanner
{
    private const int ChunkSize = 65536;

    /// <summary>Scan for overlay data after sections.</summary>
    public OverlayInfo Scan(string filePath, IReadOnlyList<SingleSectionInfo> sections, HPInfo? header = null)
    {
        var fileInfo = new FileInfo(filePath);
        long fileSize = fileInfo.Length;

        if (sections.Count == 0)
            return new OverlayInfo(0, 0, 0.0);

        // Find the end of the last section
        long maxSectionEnd = 0;
        foreach (var section in sections)
        {
            long sectionEnd = section.PointerToRawData + section.SizeOfRawData;
            if (sectionEnd > maxSectionEnd)
                maxSectionEnd = sectionEnd;
        }

        // If binary has an Authenticode signature at or after the last section,
        // it is legitimate certificate data, not malicious overlay data.
        if (header != null && header.SecurityDirectoryFileOffset > 0 && header.SecurityDirectorySize > 0)
        {
            long certEnd = header.SecurityDirectoryFileOffset + header.SecurityDirectorySize;
            if (header.SecurityDirectoryFileOffset >= maxSectionEnd)
            {
                maxSectionEnd = Math.Max(maxSectionEnd, certEnd);
            }
        }

        long overlaySize = fileSize - maxSectionEnd;
        if (overlaySize <= 0)
            return new OverlayInfo(maxSectionEnd, 0, 0.0);

        // Calculate entropy of overlay in chunks without allocating large buffers
        double entropy = 0.0;
        if (overlaySize > 0 && overlaySize < 100 * 1024 * 1024) // Max 100MB for entropy calc
        {
            using var file = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            file.Position = maxSectionEnd;

            Span<long> frequency = stackalloc long[256];
            frequency.Clear();

            byte[] buffer = new byte[ChunkSize];
            long bytesRemaining = overlaySize;

            while (bytesRemaining > 0)
            {
                int toRead = (int)Math.Min(buffer.Length, bytesRemaining);
                int bytesRead = file.Read(buffer, 0, toRead);
                if (bytesRead == 0)
                    break;

                for (int i = 0; i < bytesRead; i++)
                    frequency[buffer[i]]++;

                bytesRemaining -= bytesRead;
            }

            entropy = CalculateShannonEntropy(frequency, overlaySize - bytesRemaining);
        }

        return new OverlayInfo(maxSectionEnd, overlaySize, entropy);
    }

    private static double CalculateShannonEntropy(ReadOnlySpan<long> frequency, long totalBytes)
    {
        if (totalBytes <= 0)
            return 0.0;

        double entropy = 0.0;
        double dataLength = totalBytes;

        for (int i = 0; i < 256; i++)
        {
            if (frequency[i] == 0)
                continue;

            double probability = frequency[i] / dataLength;
            entropy -= probability * Math.Log2(probability);
        }

        return entropy;
    }
}
