using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace Scanner.Desktop.Converters;

public class RiskLevelToColorConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is string riskLevel)
        {
            return riskLevel.ToUpperInvariant() switch
            {
                "CRITICAL" => new SolidColorBrush(Color.FromRgb(220, 53, 69)),
                "HIGH" => new SolidColorBrush(Color.FromRgb(255, 193, 7)),
                "MEDIUM" => new SolidColorBrush(Color.FromRgb(255, 152, 0)),
                "LOW" => new SolidColorBrush(Color.FromRgb(76, 175, 80)),
                "INFO" => new SolidColorBrush(Color.FromRgb(33, 150, 243)),
                _ => new SolidColorBrush(Colors.Gray)
            };
        }
        return new SolidColorBrush(Colors.Gray);
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}

public class BoolToYesNoConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return value is bool b && b ? "✓" : "✗";
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}

public class FileSizeConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB" };
            double len = bytes;
            int order = 0;
            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len = len / 1024;
            }
            return $"{len:0.##} {sizes[order]}";
        }
        return "0 B";
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}

public class SeverityToColorConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is string severity)
        {
            return severity.ToUpperInvariant() switch
            {
                "CRITICAL" => new SolidColorBrush(Color.FromRgb(220, 53, 69)),
                "HIGH" => new SolidColorBrush(Color.FromRgb(255, 193, 7)),
                "MEDIUM" => new SolidColorBrush(Color.FromRgb(255, 152, 0)),
                "LOW" => new SolidColorBrush(Color.FromRgb(76, 175, 80)),
                _ => new SolidColorBrush(Colors.Gray)
            };
        }
        return new SolidColorBrush(Colors.Gray);
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}
