using Core.Analysis;
using Core.Modules;
using Core.PE;
using Core.Scanning;
using Xunit;

namespace Scanner.Tests;

public sealed class CancellationTests
{
    [Fact]
    public void PeImageParser_WithCanceledToken_ThrowsOperationCanceled()
    {
        string path = PeBuilder.WriteTemporaryPeFile();
        try
        {
            using var cts = new CancellationTokenSource();
            cts.Cancel();

            var parser = CreateParser();
            Assert.Throws<OperationCanceledException>(() => parser.Parse(path, cts.Token));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task PeScanModule_WithCanceledToken_ThrowsOperationCanceled()
    {
        string path = PeBuilder.WriteTemporaryPeFile();
        try
        {
            using var cts = new CancellationTokenSource();
            cts.Cancel();

            var module = PeScanModule.CreateDefault();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                module.ScanAsync(ScanTarget.ForPeFile(path), cts.Token));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void PeFileReader_WithCanceledRead_ThrowsOperationCanceled()
    {
        string path = PeBuilder.WriteTemporaryPeFile();
        try
        {
            using var reader = PeFileReader.Open(path);
            using var cts = new CancellationTokenSource();
            cts.Cancel();

            byte[] buffer = new byte[4];
            Assert.Throws<OperationCanceledException>(() =>
                reader.ReadExactly(0, buffer, cts.Token));
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static PeImageParser CreateParser() =>
        new(
            new HeaderParser(),
            new Core.Sections.SectionParser(),
            new Core.Parsing.LoadConfigParser(),
            new Core.Parsing.DelayImportParser(),
            new Core.Parsing.EntropyScanner(),
            new Core.Parsing.OverlayScanner(),
            new Core.Parsing.CertificateParser(),
            new Core.ImpParser.ImportedParser());
}
