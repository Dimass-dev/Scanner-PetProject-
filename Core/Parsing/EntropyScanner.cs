using Core.Analysis;
using Core.Models;

namespace Core.Parsing;

/// <summary>
/// Calculates Shannon entropy for PE sections to detect packed or encrypted code.
/// </summary>
public sealed class EntropyScanner
{
    private const int ChunkSize = 65536;

    /// <summary>Calculate entropy for all sections.</summary>
    public IReadOnlyList<SectionEntropy> CalculateEntropy(string filePath, IReadOnlyList<SingleSectionInfo> sections)
    {
        var results = new List<SectionEntropy>();

        using var file = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        long fileLength = file.Length;
        Span<long> frequency = stackalloc long[256];

        foreach (var section in sections)
        {
            if (section.SizeOfRawData == 0 || section.PointerToRawData >= fileLength)
            {
                results.Add(new SectionEntropy(
                    Name: section.Name,
                    Entropy: 0.0,
                    RawSize: section.SizeOfRawData,
                    IsExecutable: section.Flags.HasFlag(SectionFlag.MemExecute),
                    IsWritable: section.Flags.HasFlag(SectionFlag.MemWrite),
                    IsResource: section.Name.Equals(".rsrc", StringComparison.OrdinalIgnoreCase)));
                continue;
            }

            // Calculate available bytes in file
            long availableBytes = Math.Min((long)section.SizeOfRawData, fileLength - section.PointerToRawData);
            if (availableBytes <= 0)
            {
                results.Add(new SectionEntropy(
                    Name: section.Name,
                    Entropy: 0.0,
                    RawSize: section.SizeOfRawData,
                    IsExecutable: section.Flags.HasFlag(SectionFlag.MemExecute),
                    IsWritable: section.Flags.HasFlag(SectionFlag.MemWrite),
                    IsResource: section.Name.Equals(".rsrc", StringComparison.OrdinalIgnoreCase)));
                continue;
            }

            // Stream section data to count byte frequencies without large memory allocation
            frequency.Clear();

            file.Position = section.PointerToRawData;
            byte[] buffer = new byte[ChunkSize];
            long bytesRemaining = availableBytes;

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

            double entropy = CalculateShannonEntropyFromFrequencies(frequency, availableBytes - bytesRemaining);

            results.Add(new SectionEntropy(
                Name: section.Name,
                Entropy: entropy,
                RawSize: section.SizeOfRawData,
                IsExecutable: section.Flags.HasFlag(SectionFlag.MemExecute),
                IsWritable: section.Flags.HasFlag(SectionFlag.MemWrite),
                IsResource: section.Name.Equals(".rsrc", StringComparison.OrdinalIgnoreCase)));
        }

        return results;
    }

    /// <summary>Calculate Shannon entropy (0-8 bits per byte) from frequency counts.</summary>
    private static double CalculateShannonEntropyFromFrequencies(ReadOnlySpan<long> frequency, long totalBytes)
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
