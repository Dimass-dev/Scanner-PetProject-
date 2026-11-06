using Core.ImpParser;
using Core.Models;
using Core.Models.ImportDLL;
using Core.Parsing;
using Core.PE;
using Core.Sections;

namespace Core.Analysis;

/// <summary>
/// Single-pass PE file parser that builds an immutable PeImage aggregate.
/// Opens the file once and extracts all needed information.
/// </summary>
public sealed class PeImageParser
{
    private readonly HeaderParser _headerParser;
    private readonly SectionParser _sectionParser;
    private readonly LoadConfigParser _loadConfigParser;
    private readonly DelayImportParser _delayImportParser;
    private readonly EntropyScanner _entropyScanner;
    private readonly OverlayScanner _overlayScanner;
    private readonly CertificateParser _certificateParser;
    private readonly ImportedParser _importedParser;

    public PeImageParser(
        HeaderParser headerParser,
        SectionParser sectionParser,
        LoadConfigParser loadConfigParser,
        DelayImportParser delayImportParser,
        EntropyScanner entropyScanner,
        OverlayScanner overlayScanner,
        CertificateParser certificateParser,
        ImportedParser importedParser)
    {
        _headerParser = headerParser;
        _sectionParser = sectionParser;
        _loadConfigParser = loadConfigParser;
        _delayImportParser = delayImportParser;
        _entropyScanner = entropyScanner;
        _overlayScanner = overlayScanner;
        _certificateParser = certificateParser;
        _importedParser = importedParser;
    }

    /// <summary>Parse PE file into immutable aggregate.</summary>
    public Result<PeImage> Parse(string filePath, CancellationToken cancellationToken = default)
    {
        if (!File.Exists(filePath))
        {
            return Result<PeImage>.Fail($"File not found: {filePath}");
        }

        try
        {
            using var reader = PeFileReader.Open(filePath);
            return Parse(reader, filePath, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            return Result<PeImage>.Fail($"Error parsing PE file: {ex.Message}");
        }
    }

    /// <summary>Parse PE file through an already-open reader.</summary>
    public Result<PeImage> Parse(
        PeFileReader reader,
        string filePath,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(reader);

        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            // Parse header
            var headerResult = _headerParser.Parse(reader, cancellationToken);
            if (!headerResult.IsSuccess || headerResult.Info == null)
            {
                return Result<PeImage>.Fail(headerResult.ErrorMessage ?? "Failed to parse header");
            }

            var header = headerResult.Info;

            // Parse sections
            var sectionsResult = _sectionParser.Parse(reader, header, cancellationToken);
            if (!sectionsResult.IsSuccess)
            {
                return Result<PeImage>.Fail(sectionsResult.ErrorMessage ?? "Failed to parse sections");
            }

            IReadOnlyList<SingleSectionInfo> sections = sectionsResult.SectionInfo ?? new List<SingleSectionInfo>();

            // Calculate entropy for sections
            var entropy = _entropyScanner.CalculateEntropy(reader, sections, cancellationToken);

            // Parse imports using existing ImportedParser
            var imports = _importedParser.Parse(reader, header, sections, cancellationToken);

            // Parse delay imports
            var delayImports = _delayImportParser.Parse(reader, header, sections, cancellationToken);

            // Parse load config
            var loadConfig = _loadConfigParser.Parse(reader, header, sections, cancellationToken);

            // Parse certificate
            var signature = _certificateParser.Parse(reader, header, filePath, cancellationToken);

            // Scan overlay (accounting for Security Directory)
            var overlay = _overlayScanner.Scan(reader, sections, header, cancellationToken);

            var peImage = new PeImage(
                Path: filePath,
                FileSize: reader.Length,
                Header: header,
                Sections: sections,
                Entropy: entropy,
                Imports: imports,
                DelayImports: delayImports,
                LoadConfig: loadConfig,
                Signature: signature,
                Overlay: overlay);

            return Result<PeImage>.Success(peImage);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            return Result<PeImage>.Fail($"Error parsing PE file: {ex.Message}");
        }
    }
}

/// <summary>Generic result wrapper.</summary>
public sealed record Result<T>
{
    public bool IsSuccess { get; init; }
    public T? Value { get; init; }
    public string? ErrorMessage { get; init; }

    public static Result<T> Success(T value) => new()
    {
        IsSuccess = true,
        Value = value
    };

    public static Result<T> Fail(string error) => new()
    {
        IsSuccess = false,
        ErrorMessage = error
    };
}
