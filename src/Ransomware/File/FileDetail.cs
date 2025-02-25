using System.IO;

namespace Ransomware.File;

/// <summary>
/// Represents details of a scanned file.
/// </summary>
internal sealed class FileDetail(string filePath, long size)
{
    private const double KB = 1024.0;
    private const double MB = KB * 1024;
    private const double GB = MB * 1024;

    public double Size { get; } = size;
    public string FilePath { get; } = filePath;
    public string FileName => Path.GetFileName(FilePath);

    public string FormatSize() => Size switch
    {
        >= GB => $"{Size / GB:F2} GB",
        >= MB => $"{Size / MB:F2} MB",
        >= KB => $"{Size / KB:F2} KB",
        _ => $"{Size} B"
    };
}