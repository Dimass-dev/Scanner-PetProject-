using System.Buffers.Binary;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Core.Analysis;
using Core.Models;

namespace Core.Parsing;

/// <summary>
/// Parses and verifies PE Authenticode signatures using cross-platform APIs.
/// </summary>
public sealed class CertificateParser
{
    private const ushort WinCertTypePkcsSignedData = 0x0002;
    private const int WinCertificateHeaderSize = 8;
    private const int MaximumCertificateBytes = 16 * 1024 * 1024;
    private const int MaximumChainErrors = 16;

    /// <summary>Parse and verify certificate from Security Directory.</summary>
    public CertificateInfo Parse(
        string filePath,
        HPInfo header,
        CancellationToken cancellationToken = default)
    {
        if (header.SecurityDirectoryFileOffset == 0 || header.SecurityDirectorySize == 0)
        {
            return CreateUnsigned();
        }

        try
        {
            using var reader = PeFileReader.Open(filePath);
            return Parse(reader, header, filePath, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            return CreateInvalid($"Error parsing certificate: {ex.Message}");
        }
    }

    public CertificateInfo Parse(
        PeFileReader reader,
        HPInfo header,
        string? filePath = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(header);

        if (header.SecurityDirectoryFileOffset == 0 || header.SecurityDirectorySize == 0)
        {
            return CreateUnsigned();
        }

        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            long directoryOffset = header.SecurityDirectoryFileOffset;
            long directorySize = header.SecurityDirectorySize;

            if (directorySize > MaximumCertificateBytes)
            {
                return CreateInvalid($"Certificate directory exceeds the supported limit of {MaximumCertificateBytes} bytes");
            }

            if (!reader.IsRangeWithinFile(directoryOffset, directorySize))
            {
                return CreateInvalid("The certificate directory extends past the end of the file");
            }

            if (directorySize < WinCertificateHeaderSize)
            {
                return CreateInvalid("The certificate directory is too small");
            }

            // Parse WIN_CERTIFICATE structure:
            // dwLength (4 bytes), wRevision (2 bytes), wCertificateType (2 bytes)
            Span<byte> winCertificateHeader = stackalloc byte[WinCertificateHeaderSize];
            reader.ReadExactly(directoryOffset, winCertificateHeader, cancellationToken);

            uint dwLength = BinaryPrimitives.ReadUInt32LittleEndian(winCertificateHeader);
            ushort wCertificateType = BinaryPrimitives.ReadUInt16LittleEndian(winCertificateHeader[6..]);

            if (wCertificateType != WinCertTypePkcsSignedData)
            {
                return CreateInvalid("Unsupported certificate type in security directory");
            }

            if (dwLength < WinCertificateHeaderSize)
            {
                return CreateInvalid("Invalid WIN_CERTIFICATE length");
            }

            if (dwLength > directorySize)
            {
                return CreateInvalid("WIN_CERTIFICATE length exceeds the security directory size");
            }

            if (dwLength > MaximumCertificateBytes)
            {
                return CreateInvalid($"WIN_CERTIFICATE length exceeds the supported limit of {MaximumCertificateBytes} bytes");
            }

            long payloadLength = (long)dwLength - WinCertificateHeaderSize;
            if (payloadLength <= 0)
            {
                return CreateInvalid("Empty certificate payload");
            }

            if (payloadLength > int.MaxValue)
            {
                return CreateInvalid("Certificate payload is too large");
            }

            byte[] signatureData = new byte[payloadLength];
            reader.ReadExactly(directoryOffset + WinCertificateHeaderSize, signatureData, cancellationToken);

            // Parse PKCS#7 signature
            var signedCms = new SignedCms();
            signedCms.Decode(signatureData);

            if (signedCms.Certificates.Count == 0)
            {
                return CreateInvalid("No certificates found in signature");
            }

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

            // Bind the signature to the actual PE bytes.
            AuthenticodeDigestResult digestResult = AuthenticodeVerifier.VerifyDigest(
                reader,
                header,
                signedCms,
                filePath,
                cancellationToken);

            if (!digestResult.IsSupported)
            {
                return CreateInvalid(digestResult.Error ?? "Authenticode digest is not supported", signerCert);
            }

            if (!digestResult.IsMatch)
            {
                return CreateInvalid(digestResult.Error ?? "The PE digest does not match the signature", signerCert);
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
                    if (chainErrors.Count >= MaximumChainErrors)
                    {
                        break;
                    }

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
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
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
        {
            return SignatureState.Expired;
        }

        // Check chain trust
        if (!chainValid)
        {
            bool isTrustIssueOnly = errors.Count > 0 && errors.All(e =>
                e.Contains("UntrustedRoot", StringComparison.OrdinalIgnoreCase) ||
                e.Contains("PartialChain", StringComparison.OrdinalIgnoreCase) ||
                e.Contains("RevocationStatusUnknown", StringComparison.OrdinalIgnoreCase) ||
                e.Contains("OfflineRevocation", StringComparison.OrdinalIgnoreCase));

            if (isTrustIssueOnly)
            {
                return SignatureState.Untrusted;
            }

            return SignatureState.Invalid;
        }

        return SignatureState.Valid;
    }

    private static CertificateInfo CreateUnsigned() =>
        new(SignatureState.Unsigned, null, null, null, null, null, Array.Empty<string>());

    private static CertificateInfo CreateInvalid(string error, X509Certificate2? cert = null) =>
        new(
            State: SignatureState.Invalid,
            SubjectName: cert?.Subject,
            IssuerName: cert?.Issuer,
            NotBefore: cert?.NotBefore,
            NotAfter: cert?.NotAfter,
            Thumbprint: cert?.Thumbprint,
            ChainErrors: new[] { error });
}
