using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using Core.Analysis;
using Core.Models;

namespace Core.Parsing;

public sealed record AuthenticodeDigestResult(
    bool IsSupported,
    bool IsMatch,
    string? Error);

/// <summary>
/// Binds an Authenticode signature to the actual PE bytes by comparing the digest
/// in SpcIndirectDataContent with the canonical PE image digest.
/// </summary>
public static class AuthenticodeVerifier
{
    private const string Sha1Oid = "1.3.14.3.2.26";
    private const string Sha256Oid = "2.16.840.1.101.3.4.2.1";
    private const string Sha384Oid = "2.16.840.1.101.3.4.2.2";
    private const string Sha512Oid = "2.16.840.1.101.3.4.2.3";

    public static AuthenticodeDigestResult VerifyDigest(
        PeFileReader reader,
        HPInfo header,
        SignedCms signedCms,
        string? filePath = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(header);
        ArgumentNullException.ThrowIfNull(signedCms);

        if (!TryReadDigestInfo(signedCms, out HashAlgorithmName algorithm, out byte[] expectedDigest, out string? readError))
        {
            return new AuthenticodeDigestResult(false, false, readError);
        }

        try
        {
            byte[] actualDigest = PeAuthenticodeHasher.ComputeDigest(
                reader,
                header,
                algorithm,
                cancellationToken);

            if (!CryptographicOperations.FixedTimeEquals(actualDigest, expectedDigest))
            {
                return new AuthenticodeDigestResult(true, false, "The PE digest does not match the signature digest.");
            }

            if (OperatingSystem.IsWindows())
            {
                WinVerifyTrustOutcome outcome = WinVerifyTrust.TryVerify(filePath, out string? winTrustError);
                if (outcome == WinVerifyTrustOutcome.BadDigest)
                {
                    return new AuthenticodeDigestResult(true, false, winTrustError ?? "WinVerifyTrust rejected the PE digest.");
                }
            }

            return new AuthenticodeDigestResult(true, true, null);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            return new AuthenticodeDigestResult(false, false, $"Authenticode digest verification failed: {ex.Message}");
        }
    }

    public static bool TryReadDigestInfo(
        SignedCms signedCms,
        out HashAlgorithmName algorithm,
        out byte[] digest,
        out string? error)
    {
        algorithm = default;
        digest = [];
        error = null;

        try
        {
            AsnReader reader = new(signedCms.ContentInfo.Content, AsnEncodingRules.BER);
            AsnReader content = reader.ReadSequence();

            // SpcAttributeTypeAndOptionalValue (data)
            content.ReadSequence();

            // DigestInfo
            AsnReader digestInfo = content.ReadSequence();
            AsnReader algorithmIdentifier = digestInfo.ReadSequence();
            string oid = algorithmIdentifier.ReadObjectIdentifier();
            if (algorithmIdentifier.HasData)
            {
                algorithmIdentifier.ReadEncodedValue();
            }

            algorithm = oid switch
            {
                Sha1Oid => HashAlgorithmName.SHA1,
                Sha256Oid => HashAlgorithmName.SHA256,
                Sha384Oid => HashAlgorithmName.SHA384,
                Sha512Oid => HashAlgorithmName.SHA512,
                _ => default
            };

            if (algorithm == default)
            {
                error = $"Unsupported signature digest algorithm OID {oid}.";
                return false;
            }

            digest = digestInfo.ReadOctetString();
            if (digest.Length == 0)
            {
                error = "The signature contains an empty digest.";
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            error = $"Unable to read SpcIndirectDataContent: {ex.Message}";
            return false;
        }
    }
}
