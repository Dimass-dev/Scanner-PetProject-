using System.Buffers;
using System.Security.Cryptography;
using Core.Analysis;
using Core.Models;
using Core.PE;

namespace Core.Parsing;

/// <summary>
/// Computes the PE image digest used by Authenticode.
/// The checksum, the security-directory entry, and the certificate table are excluded.
/// </summary>
public static class PeAuthenticodeHasher
{
    private const int BufferSize = 65536;

    public static byte[] ComputeDigest(
        PeFileReader reader,
        HPInfo header,
        HashAlgorithmName hashAlgorithm,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(header);

        int optionalHeaderOffset = checked(header.PeOffset + 4 + 20);
        int checkSumOffset = checked(optionalHeaderOffset + 64);
        int dataDirectoriesOffset = checked(optionalHeaderOffset + (header.IsPE32Plus ? 112 : 96));
        int securityDirectoryOffset = checked(dataDirectoriesOffset + 4 * 8);

        long headerSize = Math.Min((long)header.SizeOfHeaders, reader.Length);
        if (headerSize <= 0)
        {
            throw new InvalidDataException("The PE header size is invalid.");
        }

        if (!reader.IsRangeWithinFile(optionalHeaderOffset, header.SizeOfOptionalHeader))
        {
            throw new InvalidDataException("The PE optional header extends past the end of the file.");
        }

        if (checkSumOffset < 0 || checkSumOffset + 4 > headerSize ||
            securityDirectoryOffset < 0 || securityDirectoryOffset + 8 > headerSize)
        {
            throw new InvalidDataException("The PE header is too small for Authenticode fields.");
        }

        using var hash = IncrementalHash.CreateHash(hashAlgorithm);
        byte[] buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
        try
        {
            AppendRange(hash, reader, 0, checkSumOffset, buffer, cancellationToken);
            AppendRange(hash, reader, checkSumOffset + 4, securityDirectoryOffset - (checkSumOffset + 4), buffer, cancellationToken);
            AppendRange(hash, reader, securityDirectoryOffset + 8, headerSize - (securityDirectoryOffset + 8), buffer, cancellationToken);

            long maxSectionEnd = headerSize;
            foreach (var section in header.NumberOfSections == 0
                ? Array.Empty<SingleSectionInfo>()
                : GetSectionsInFileOrder(reader, header))
            {
                cancellationToken.ThrowIfCancellationRequested();

                long sectionStart = section.PointerToRawData;
                long sectionLength = Math.Min((long)section.SizeOfRawData, reader.Length - sectionStart);
                if (sectionLength <= 0)
                {
                    continue;
                }

                AppendRange(hash, reader, sectionStart, sectionLength, buffer, cancellationToken);
                maxSectionEnd = Math.Max(maxSectionEnd, sectionStart + sectionLength);
            }

            AppendTail(hash, reader, header, maxSectionEnd, buffer, cancellationToken);
            return hash.GetHashAndReset();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static IEnumerable<SingleSectionInfo> GetSectionsInFileOrder(PeFileReader reader, HPInfo header)
    {
        if (header.NumberOfSections <= 0 || header.SectionOffset < 0)
        {
            yield break;
        }

        int tableSize = checked(header.NumberOfSections * 40);
        if (!reader.IsRangeWithinFile(header.SectionOffset, tableSize))
        {
            yield break;
        }

        byte[] table = new byte[tableSize];
        reader.ReadExactly(header.SectionOffset, table);

        var sections = new List<(uint Pointer, uint Size, string Name)>(header.NumberOfSections);
        for (int index = 0; index < header.NumberOfSections; index++)
        {
            int start = index * 40;
            uint size = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(table.AsSpan(start + 16));
            uint pointer = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(table.AsSpan(start + 20));
            if (pointer == 0 || size == 0)
            {
                continue;
            }

            sections.Add((pointer, size, string.Empty));
        }

        sections.Sort((left, right) => left.Pointer.CompareTo(right.Pointer));
        foreach (var section in sections)
        {
            yield return new SingleSectionInfo
            {
                SectionName = section.Name,
                SizeOfRawData = section.Size,
                PointerToRawData = section.Pointer
            };
        }
    }

    private static void AppendTail(
        IncrementalHash hash,
        PeFileReader reader,
        HPInfo header,
        long tailStart,
        byte[] buffer,
        CancellationToken cancellationToken)
    {
        if (tailStart >= reader.Length)
        {
            return;
        }

        long certStart = header.SecurityDirectoryFileOffset;
        long certSize = header.SecurityDirectorySize;
        long certEnd = certStart > long.MaxValue - certSize ? long.MaxValue : certStart + certSize;

        if (certStart >= tailStart && certStart < reader.Length)
        {
            AppendRange(hash, reader, tailStart, certStart - tailStart, buffer, cancellationToken);
            long afterCertificate = Math.Max(certEnd, tailStart);
            if (afterCertificate < reader.Length)
            {
                AppendRange(hash, reader, afterCertificate, reader.Length - afterCertificate, buffer, cancellationToken);
            }

            return;
        }

        AppendRange(hash, reader, tailStart, reader.Length - tailStart, buffer, cancellationToken);
    }

    private static void AppendRange(
        IncrementalHash hash,
        PeFileReader reader,
        long offset,
        long length,
        byte[] buffer,
        CancellationToken cancellationToken)
    {
        if (length <= 0)
        {
            return;
        }

        if (!reader.IsRangeWithinFile(offset, length))
        {
            throw new InvalidDataException("An Authenticode range extends past the end of the file.");
        }

        long remaining = length;
        long current = offset;
        while (remaining > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();

            int chunk = (int)Math.Min(buffer.Length, remaining);
            reader.ReadExactly(current, buffer.AsSpan(0, chunk), cancellationToken);
            hash.AppendData(buffer, 0, chunk);

            current += chunk;
            remaining -= chunk;
        }
    }
}
