namespace Core.Utils;

/// <summary>Shared Shannon entropy math used by the section and overlay scanners.</summary>
public static class ShannonEntropy
{
    /// <summary>Calculate Shannon entropy (0-8 bits per byte) from frequency counts.</summary>
    public static double FromFrequencies(ReadOnlySpan<long> frequency, long totalBytes)
    {
        if (totalBytes <= 0)
        {
            return 0.0;
        }

        double entropy = 0.0;
        double dataLength = totalBytes;

        for (int i = 0; i < 256; i++)
        {
            if (frequency[i] == 0)
            {
                continue;
            }

            double probability = frequency[i] / dataLength;
            entropy -= probability * Math.Log2(probability);
        }

        return entropy;
    }
}
