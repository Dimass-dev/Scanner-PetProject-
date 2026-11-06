using System.Buffers.Binary;
using System.Security.Cryptography.Pkcs;
using Core.Analysis;
using Core.Models;
using Core.Parsing;
using Core.PE;
using Xunit;

namespace Scanner.Tests;

public sealed class AuthenticodeTests
{
    [Fact]
    public void SignedPe_DigestMatchesSignature()
    {
        string path = SignedPeBuilder.WriteSignedPeFile(out _);
        try
        {
            using var reader = PeFileReader.Open(path);
            var header = new HeaderParser().Parse(reader);
            Assert.True(header.IsSuccess, header.ErrorMessage);
            Assert.NotNull(header.Info);

            SignedCms signedCms = ReadSignature(reader, header.Info);
            AuthenticodeDigestResult result = AuthenticodeVerifier.VerifyDigest(
                reader,
                header.Info,
                signedCms,
                path);

            Assert.True(result.IsSupported, result.Error);
            Assert.True(result.IsMatch, result.Error);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void TamperedSection_DigestDoesNotMatch()
    {
        string path = SignedPeBuilder.WriteSignedPeFile(out byte[] signedImage);
        try
        {
            signedImage[PeBuilder.RawSectionOffset + 10] ^= 0x5A;
            File.WriteAllBytes(path, signedImage);

            using var reader = PeFileReader.Open(path);
            var header = new HeaderParser().Parse(reader);
            Assert.True(header.IsSuccess, header.ErrorMessage);
            Assert.NotNull(header.Info);

            SignedCms signedCms = ReadSignature(reader, header.Info);
            AuthenticodeDigestResult result = AuthenticodeVerifier.VerifyDigest(
                reader,
                header.Info,
                signedCms,
                path);

            Assert.True(result.IsSupported, result.Error);
            Assert.False(result.IsMatch);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void TamperedSignedPe_CertificateParserReturnsInvalid()
    {
        string path = SignedPeBuilder.WriteSignedPeFile(out byte[] signedImage);
        try
        {
            signedImage[PeBuilder.RawSectionOffset + 20] ^= 0x33;
            File.WriteAllBytes(path, signedImage);

            using var reader = PeFileReader.Open(path);
            var header = new HeaderParser().Parse(reader);
            Assert.True(header.IsSuccess, header.ErrorMessage);
            Assert.NotNull(header.Info);

            var certificate = new CertificateParser().Parse(reader, header.Info, path);
            Assert.Equal(SignatureState.Invalid, certificate.State);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void OversizedCertificateDirectory_ReturnsInvalid()
    {
        byte[] image = PeBuilder.CreatePe64();
        int optionalHeaderOffset = PeBuilder.PeOffset + 4 + 20;
        int securityDirectoryOffset = optionalHeaderOffset + 112 + 4 * 8;

        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(securityDirectoryOffset, 4), PeBuilder.FileSize);
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(securityDirectoryOffset + 4, 4), 16 * 1024 * 1024 + 1);

        string path = PeBuilder.WriteTemporaryPeFile(image);
        try
        {
            var certificate = new CertificateParser().Parse(path, new HeaderParser().Parse(path).Info!);
            Assert.Equal(SignatureState.Invalid, certificate.State);
            Assert.Contains("supported limit", certificate.ChainErrors[0], StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static SignedCms ReadSignature(PeFileReader reader, HPInfo header)
    {
        Span<byte> winCertificateHeader = stackalloc byte[8];
        reader.ReadExactly(header.SecurityDirectoryFileOffset, winCertificateHeader);

        uint length = BinaryPrimitives.ReadUInt32LittleEndian(winCertificateHeader);
        byte[] payload = new byte[length - 8];
        reader.ReadExactly(header.SecurityDirectoryFileOffset + 8, payload);

        var signedCms = new SignedCms();
        signedCms.Decode(payload);
        return signedCms;
    }
}
