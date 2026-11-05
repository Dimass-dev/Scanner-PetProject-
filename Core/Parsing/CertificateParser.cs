using Core.Analysis;
using Core.Models;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace Core.Parsing;

/// <summary>
/// Parses and verifies PE Authenticode signatures using cross-platform APIs.
/// </summary>
public sealed class CertificateParser
{
    private const ushort WinCertTypePkcsSignedData = 0x0002;

    /// <summary>Parse and verify certificate from Security Directory.</summary>
    public CertificateInfo Parse(string filePath, HPInfo header)
    {
        if (header.SecurityDirectoryFileOffset == 0 || header.SecurityDirectorySize == 0)
            return CreateUnsigned();

        try
        {
            using var file = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);

            if (header.SecurityDirectoryFileOffset + header.SecurityDirectorySize > file.Length)
                return CreateUnsigned();

            // Read certificate data
            file.Position = header.SecurityDirectoryFileOffset;
            byte[] certData = new byte[header.SecurityDirectorySize];
            file.ReadExactly(certData);

            // Parse WIN_CERTIFICATE structure:
            // dwLength (4 bytes), wRevision (2 bytes), wCertificateType (2 bytes)
            if (certData.Length < 8)
                return CreateUnsigned();

            uint dwLength = BinaryPrimitives.ReadUInt32LittleEndian(certData.AsSpan(0, 4));
            ushort wRevision = BinaryPrimitives.ReadUInt16LittleEndian(certData.AsSpan(4, 2));
            ushort wCertificateType = BinaryPrimitives.ReadUInt16LittleEndian(certData.AsSpan(6, 2));

            if (wCertificateType != WinCertTypePkcsSignedData || dwLength < 8)
                return CreateInvalid("Unsupported certificate type in security directory");

            int payloadLength = (int)Math.Min((long)dwLength - 8, certData.Length - 8);
            if (payloadLength <= 0)
                return CreateInvalid("Empty certificate payload");

            byte[] signatureData = certData[8..(8 + payloadLength)];

            // Parse PKCS#7 signature
            var signedCms = new SignedCms();
            signedCms.Decode(signatureData);

            if (signedCms.Certificates.Count == 0)
                return CreateInvalid("No certificates found in signature");

            var signerCert = signedCms.Certificates[0];

            // Verify signature
            try
            {
                signedCms.CheckSignature(verifySignatureOnly: true);
            }
            catch
            {
                return CreateInvalid("Signature verification failed", signerCert);
            }

            // Build and verify certificate chain
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; // Avoid network calls
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid;

            bool chainValid = chain.Build(signerCert);
            var chainErrors = new List<string>();

            if (!chainValid)
            {
                foreach (var chainStatus in chain.ChainStatus)
                {
                    chainErrors.Add($"{chainStatus.Status}: {chainStatus.StatusInformation}");
                }
            }

            // Determine state
            SignatureState state = DetermineState(signerCert, chainValid, chainErrors);

            return new CertificateInfo(
                State: state,
                SubjectName: signerCert.Subject,
                IssuerName: signerCert.Issuer,
                NotBefore: signerCert.NotBefore,
                NotAfter: signerCert.NotAfter,
                Thumbprint: signerCert.Thumbprint,
                ChainErrors: chainErrors);
        }
        catch (Exception ex)
        {
            return CreateInvalid($"Error parsing certificate: {ex.Message}");
        }
    }

    private SignatureState DetermineState(X509Certificate2 cert, bool chainValid, List<string> errors)
    {
        // Check expiration
        DateTime now = DateTime.UtcNow;
        if (now < cert.NotBefore || now > cert.NotAfter)
            return SignatureState.Expired;

        // Check chain trust
        if (!chainValid)
        {
            bool isTrustIssueOnly = errors.Count > 0 && errors.All(e =>
                e.Contains("UntrustedRoot", StringComparison.OrdinalIgnoreCase) ||
                e.Contains("PartialChain", StringComparison.OrdinalIgnoreCase) ||
                e.Contains("RevocationStatusUnknown", StringComparison.OrdinalIgnoreCase) ||
                e.Contains("OfflineRevocation", StringComparison.OrdinalIgnoreCase));

            if (isTrustIssueOnly)
                return SignatureState.Untrusted;

            return SignatureState.Invalid;
        }

        return SignatureState.Valid;
    }

    private CertificateInfo CreateUnsigned() =>
        new(SignatureState.Unsigned, null, null, null, null, null, Array.Empty<string>());

    private CertificateInfo CreateInvalid(string error, X509Certificate2? cert = null) =>
        new(
            State: SignatureState.Invalid,
            SubjectName: cert?.Subject,
            IssuerName: cert?.Issuer,
            NotBefore: cert?.NotBefore,
            NotAfter: cert?.NotAfter,
            Thumbprint: cert?.Thumbprint,
            ChainErrors: new[] { error });
}
