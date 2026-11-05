namespace Core.Scanning;

/// <summary>Selects compatible modules and combines their output into the common report model.</summary>
public sealed class ScanCoordinator(IEnumerable<IScanModule> modules)
{
    private readonly IReadOnlyList<IScanModule> _modules = modules?.ToArray()
        ?? throw new ArgumentNullException(nameof(modules));

    public async Task<ScanReport> ScanAsync(ScanTarget target, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(target);
        if (string.IsNullOrWhiteSpace(target.Value))
        {
            return new ScanReport(target, [ScanModuleResult.Failure("coordinator", "A scan target is required.")]);
        }

        IScanModule[] selected = _modules.Where(module => module.Supports(target.Kind)).ToArray();
        if (selected.Length == 0)
        {
            return new ScanReport(target, []);
        }

        var results = new List<ScanModuleResult>(selected.Length);
        foreach (IScanModule module in selected)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                ScanModuleResult result = await module.ScanAsync(target, cancellationToken).ConfigureAwait(false);
                results.Add(result);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                results.Add(ScanModuleResult.Failure(module.ModuleId, exception.Message));
            }
        }

        return new ScanReport(target, results);
    }
}
