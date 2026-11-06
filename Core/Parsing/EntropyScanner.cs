using Core.Analysis;
using Core.Utils;
using Core.Models;

namespace Core.Parsing;

/// <summary>
/// Calculates Shannon entropy for PE sections to detect packed or encrypted code.
/// </summary>
public sealed class EntropyScanner
{
    private const int ChunkSize = 65536;

    /// <summary>Calculate entropy for all sections.</summary>
    public IReadOnlyList<SectionEntropy> CalculateEntropy(
        string filePath,
        IReadOnlyList<SingleSectionInfo> sections,
        CancellationToken cancellationToken = default)
    {
        using var reader = PeFileReader.Open(filePath);
        return CalculateEntropy(reader, sections, cancellationToken);
    }

    public IReadOnlyList<SectionEntropy> CalculateEntropy(
        PeFileReader reader,
        IReadOnlyList<SingleSectionInfo> sections,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(sections);

        var results = new List<SectionEntropy>(sections.Count);
        long fileLength = reader.Length;
        Span<long> frequency = stackalloc long[256];

        foreach (var section in sections)
        {
            cancellationToken.ThrowIfCancellationRequested();

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

            long bytesRemaining = availableBytes;
            byte[] buffer = new byte[ChunkSize];

            while (bytesRemaining > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();

                int toRead = (int)Math.Min(buffer.Length, bytesRemaining);
                int bytesRead = reader.Read(
                    section.PointerToRawData + (availableBytes - bytesRemaining),
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

            double entropy = ShannonEntropy.FromFrequencies(frequency, availableBytes - bytesRemaining);

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

}
