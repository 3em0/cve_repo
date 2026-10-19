param(
    [Parameter(Mandatory = $true)][int]$TargetPid,
    [Parameter(Mandatory = $true)][string]$Text,
    [switch]$NoEnter
)

# Inject keystrokes straight into another process's console input buffer.
# No window focus, no clipboard, no IME: the console host delivers the records to
# whatever console application is attached to that console.
Add-Type @"
using System;
using System.Runtime.InteropServices;

public static class ConInject {
    [StructLayout(LayoutKind.Sequential)]
    public struct KEY_EVENT_RECORD {
        public int bKeyDown;
        public ushort wRepeatCount;
        public ushort wVirtualKeyCode;
        public ushort wVirtualScanCode;
        public char UnicodeChar;
        public uint dwControlKeyState;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct INPUT_RECORD {
        [FieldOffset(0)] public ushort EventType;
        [FieldOffset(4)] public KEY_EVENT_RECORD KeyEvent;
    }

    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool FreeConsole();
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool AttachConsole(uint dwProcessId);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr GetStdHandle(int nStdHandle);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool WriteConsoleInputW(IntPtr hConsoleInput, INPUT_RECORD[] lpBuffer, uint nLength, out uint lpNumberOfEventsWritten);
    [DllImport("user32.dll")] public static extern short VkKeyScan(char ch);
    [DllImport("kernel32.dll")] public static extern uint GetLastError();

    public static string Send(string text, bool enter) {
        FreeConsole();
        if (!AttachConsole((uint)TargetPidStatic)) return "AttachConsole failed: " + GetLastError();
        // The std handles of this process are stale after AttachConsole, so open the
        // console input buffer explicitly.
        IntPtr h = CreateFileW("CONIN$", 0xC0000000u /*GENERIC_READ|GENERIC_WRITE*/, 3u /*FILE_SHARE_READ|WRITE*/,
                               IntPtr.Zero, 3u /*OPEN_EXISTING*/, 0u, IntPtr.Zero);
        if (h == IntPtr.Zero || h == (IntPtr)(-1)) {
            h = GetStdHandle(-10);
            if (h == IntPtr.Zero || h == (IntPtr)(-1)) return "no console input handle: " + GetLastError();
        }
        var recs = new System.Collections.Generic.List<INPUT_RECORD>();
        foreach (char c in text) {
            short vk = VkKeyScan(c);
            ushort v = (ushort)(vk & 0xFF);
            if (v == 0) v = 0x20;
            recs.Add(Make(true, v, c));
            recs.Add(Make(false, v, c));
        }
        if (enter) {
            recs.Add(Make(true, 0x0D, '\r'));
            recs.Add(Make(false, 0x0D, '\r'));
        }
        uint written;
        if (!WriteConsoleInputW(h, recs.ToArray(), (uint)recs.Count, out written))
            return "WriteConsoleInput failed: " + GetLastError();
        return "OK written=" + written;
    }

    public static int TargetPidStatic;

    static INPUT_RECORD Make(bool down, ushort vk, char ch) {
        var r = new INPUT_RECORD();
        r.EventType = 0x0001; // KEY_EVENT
        r.KeyEvent.bKeyDown = down ? 1 : 0;
        r.KeyEvent.wRepeatCount = 1;
        r.KeyEvent.wVirtualKeyCode = vk;
        r.KeyEvent.wVirtualScanCode = 0;
        r.KeyEvent.UnicodeChar = ch;
        r.KeyEvent.dwControlKeyState = 0;
        return r;
    }
}
"@

[ConInject]::TargetPidStatic = $TargetPid
$res = [ConInject]::Send($Text, -not $NoEnter)
Write-Output $res
