using System.Buffers.Binary;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Core.Analysis;
using Core.Models;
using Core.Parsing;
using Core.PE;

namespace Scanner.Tests;

internal static class SignedPeBuilder
{
    private const string SpcIndirectDataOid = "1.3.6.1.4.1.311.2.1.4";
    private const string SpcPeImageDataOid = "1.3.6.1.4.1.311.2.1.15";
    private const string Sha256Oid = "2.16.840.1.101.3.4.2.1";

    public static string WriteSignedPeFile(out byte[] signedImage)
    {
        byte[] peImage = PeBuilder.CreatePe64();
        int certificateOffset = PeBuilder.FileSize;
        int optionalHeaderOffset = PeBuilder.PeOffset + 4 + 20;
        int securityDirectoryOffset = optionalHeaderOffset + 112 + 4 * 8;

        BinaryPrimitives.WriteUInt32LittleEndian(
            peImage.AsSpan(securityDirectoryOffset, 4),
            (uint)certificateOffset);

        byte[] digest = ComputeDigest(peImage);
        byte[] signature = CreateSignature(digest);

        int certificateSize = 8 + signature.Length;
        Array.Resize(ref peImage, certificateOffset + certificateSize);

        Span<byte> certificate = peImage.AsSpan(certificateOffset, certificateSize);
        BinaryPrimitives.WriteUInt32LittleEndian(certificate, (uint)certificateSize);
        BinaryPrimitives.WriteUInt16LittleEndian(certificate[4..], 0x0200);
        BinaryPrimitives.WriteUInt16LittleEndian(certificate[6..], 0x0002);
        signature.CopyTo(certificate[8..]);

        BinaryPrimitives.WriteUInt32LittleEndian(
            peImage.AsSpan(securityDirectoryOffset + 4, 4),
            (uint)certificateSize);

        signedImage = peImage;
        string path = Path.Combine(Path.GetTempPath(), $"scanner-signed-{Guid.NewGuid():N}.exe");
        File.WriteAllBytes(path, peImage);
        return path;
    }

    public static byte[] ComputeDigest(byte[] peImage)
    {
        string path = Path.Combine(Path.GetTempPath(), $"scanner-digest-{Guid.NewGuid():N}.exe");
        File.WriteAllBytes(path, peImage);
        try
        {
            using var reader = PeFileReader.Open(path);
            var header = new HeaderParser().Parse(reader);
            Assert.True(header.IsSuccess, header.ErrorMessage);
            Assert.NotNull(header.Info);
            return PeAuthenticodeHasher.ComputeDigest(reader, header.Info, HashAlgorithmName.SHA256);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static byte[] CreateSignature(byte[] digest)
    {
        byte[] content = CreateSpcIndirectDataContent(digest);

        using RSA rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=Scanner Test Signer",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        using X509Certificate2 certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1));

        var signedCms = new SignedCms(new ContentInfo(new Oid(SpcIndirectDataOid), content));
        var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, certificate)
        {
            DigestAlgorithm = new Oid(Sha256Oid),
            IncludeOption = X509IncludeOption.EndCertOnly
        };

        signedCms.ComputeSignature(signer);
        return signedCms.Encode();
    }

    private static byte[] CreateSpcIndirectDataContent(byte[] digest)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);

        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(SpcPeImageDataOid);
            }

            using (writer.PushSequence())
            {
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(Sha256Oid);
                    writer.WriteNull();
                }

                writer.WriteOctetString(digest);
            }
        }

        return writer.Encode();
    }
}
