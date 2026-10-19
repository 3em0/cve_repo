# console_send.ps1 -- write one command line into another process's console input buffer.
#
# Why a separate process: AttachConsole() must be called by a process that first
# gives up its own console (FreeConsole).  Running it here keeps the caller's
# console and output untouched.
#
# Why not keystroke injection: on a machine where several agent sessions drive
# their own terminals at the same time, both the shared clipboard and the
# foreground window are contended, and the Chinese IME / Ctrl modifier state can
# mangle injected characters (observed: "Galaxyn" -> "Gala^N", "echo" -> "mecho").
# Writing KEY_EVENT records straight into the target console's input buffer is
# immune to all of that: no focus, no clipboard, no layout, no modifier state.
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File console_send.ps1 `
#       -TargetPid 1234 -TextB64 <base64-utf8-of-the-command-line> [-DelayMs 8]

param(
    [Parameter(Mandatory = $true)][int]$TargetPid,
    [Parameter(Mandatory = $true)][string]$TextB64,
    [int]$DelayMs = 8
)

$ErrorActionPreference = "Stop"

Add-Type @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class ConInj {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct KEY_EVENT_RECORD {
        public int bKeyDown;
        public ushort wRepeatCount;
        public ushort wVirtualKeyCode;
        public ushort wVirtualScanCode;
        public char UnicodeChar;
        public uint dwControlKeyState;
    }
    [StructLayout(LayoutKind.Explicit, CharSet = CharSet.Unicode)]
    public struct INPUT_RECORD {
        [FieldOffset(0)] public ushort EventType;
        [FieldOffset(4)] public KEY_EVENT_RECORD KeyEvent;
    }
    public const ushort KEY_EVENT = 0x0001;
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool FreeConsole();
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool AttachConsole(uint pid);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sec, uint disp, uint flags, IntPtr tmpl);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteConsoleInputW(IntPtr h, INPUT_RECORD[] buf, uint len, out uint written);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
    public static readonly IntPtr INVALID = new IntPtr(-1);

    public static INPUT_RECORD Rec(bool down, char c, ushort vk) {
        INPUT_RECORD r = new INPUT_RECORD();
        r.EventType = KEY_EVENT;
        r.KeyEvent.bKeyDown = down ? 1 : 0;
        r.KeyEvent.wRepeatCount = 1;
        r.KeyEvent.wVirtualKeyCode = vk;
        r.KeyEvent.wVirtualScanCode = 0;
        r.KeyEvent.UnicodeChar = c;
        r.KeyEvent.dwControlKeyState = 0;
        return r;
    }

    public static IntPtr Attach(uint pid) {
        FreeConsole();
        if (!AttachConsole(pid)) return INVALID;
        IntPtr h = CreateFileW("CONIN$", 0x40000000u | 0x80000000u, 3u, IntPtr.Zero, 3u, 0, IntPtr.Zero);
        if (h == INVALID) FreeConsole();
        return h;
    }
    public static string WriteChunk(IntPtr h, string s) {
        var recs = new List<INPUT_RECORD>();
        foreach (char c in s) { recs.Add(Rec(true, c, 0)); recs.Add(Rec(false, c, 0)); }
        uint w;
        if (!WriteConsoleInputW(h, recs.ToArray(), (uint)recs.Count, out w))
            return "WriteConsoleInput failed err=" + Marshal.GetLastWin32Error();
        return "ok " + w;
    }
    public static string Enter(IntPtr h) {
        var recs = new INPUT_RECORD[] { Rec(true, '\r', 0x0D), Rec(false, '\r', 0x0D) };
        uint w;
        if (!WriteConsoleInputW(h, recs, 2, out w))
            return "WriteConsoleInput failed err=" + Marshal.GetLastWin32Error();
        return "ok " + w;
    }
    public static void Detach(IntPtr h) { if (h != INVALID) CloseHandle(h); FreeConsole(); }
}
"@

$text = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($TextB64))

$h = [ConInj]::Attach([uint32]$TargetPid)
if ($h -eq [ConInj]::INVALID) {
    Write-Output ("ERROR attach failed for pid " + $TargetPid)
    exit 2
}
try {
    if ($DelayMs -le 0) {
        $null = [ConInj]::WriteChunk($h, $text)
    }
    else {
        foreach ($ch in $text.ToCharArray()) {
            $null = [ConInj]::WriteChunk($h, "$ch")
            Start-Sleep -Milliseconds $DelayMs
        }
    }
    Start-Sleep -Milliseconds 150
    $null = [ConInj]::Enter($h)
}
finally {
    [ConInj]::Detach($h)
}
Write-Output "SENT"
