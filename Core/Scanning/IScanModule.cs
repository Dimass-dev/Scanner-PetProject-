namespace Core.Scanning;

/// <summary>Independent analysis module contract; implementations are registered by the host.</summary>
public interface IScanModule
{
    string ModuleId { get; }
    bool Supports(ScanTargetKind targetKind);
    Task<ScanModuleResult> ScanAsync(ScanTarget target, CancellationToken cancellationToken = default);
}
