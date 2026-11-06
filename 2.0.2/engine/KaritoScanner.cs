using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class KaritoUsn
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr sec, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DeviceIoControl(SafeFileHandle h, uint code, IntPtr inBuf, int inSize, IntPtr outBuf, int outSize, out int returned, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern uint QueryDosDevice(string device, StringBuilder target, int max);

    public static string DosDevice(string drive)
    {
        StringBuilder sb = new StringBuilder(1024);
        uint n = QueryDosDevice(drive, sb, sb.Capacity);
        if (n == 0) return null;
        return sb.ToString();
    }

    public static List<string> Read(string drive, int days, string[] exts, out long firstTime)
    {
        firstTime = 0;
        List<string> result = new List<string>();
        SafeFileHandle h = CreateFile("\\\\.\\" + drive, 0x80000000, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (h.IsInvalid) throw new Exception("USN_ERROR_" + Marshal.GetLastWin32Error());
        try
        {
            long journalId = 0;
            long startUsn = 0;
            IntPtr q = Marshal.AllocHGlobal(128);
            try
            {
                int ret;
                if (!DeviceIoControl(h, 0x000900f4, IntPtr.Zero, 0, q, 128, out ret, IntPtr.Zero))
                    throw new Exception("USN_ERROR_" + Marshal.GetLastWin32Error());
                journalId = Marshal.ReadInt64(q, 0);
                startUsn = Marshal.ReadInt64(q, 8);
            }
            finally { Marshal.FreeHGlobal(q); }

            long cutoff = DateTime.UtcNow.AddDays(-days).ToFileTimeUtc();
            int bufSize = 65536;
            IntPtr input = Marshal.AllocHGlobal(40);
            IntPtr buf = Marshal.AllocHGlobal(bufSize);
            long total = 0;
            bool first = true;
            try
            {
                while (total < 2147483648L)
                {
                    Marshal.WriteInt64(input, 0, startUsn);
                    Marshal.WriteInt32(input, 8, unchecked((int)0xFFFFFFFF));
                    Marshal.WriteInt32(input, 12, 0);
                    Marshal.WriteInt64(input, 16, 0);
                    Marshal.WriteInt64(input, 24, 0);
                    Marshal.WriteInt64(input, 32, journalId);
                    int got;
                    if (!DeviceIoControl(h, 0x000900bb, input, 40, buf, bufSize, out got, IntPtr.Zero)) break;
                    if (got <= 8) break;
                    total += got;
                    long nextUsn = Marshal.ReadInt64(buf, 0);
                    int off = 8;
                    while (off + 60 <= got)
                    {
                        int len = Marshal.ReadInt32(buf, off);
                        if (len <= 0 || off + len > got) break;
                        short major = Marshal.ReadInt16(buf, off + 4);
                        if (major == 2)
                        {
                            long ts = Marshal.ReadInt64(buf, off + 32);
                            uint reason = (uint)Marshal.ReadInt32(buf, off + 40);
                            int nameLen = Marshal.ReadInt16(buf, off + 56);
                            int nameOff = Marshal.ReadInt16(buf, off + 58);
                            if (first) { firstTime = ts; first = false; }
                            if (ts >= cutoff && (reason & 0x3200) != 0 && nameLen > 0 && off + nameOff + nameLen <= got)
                            {
                                string name = Marshal.PtrToStringUni(new IntPtr(buf.ToInt64() + off + nameOff), nameLen / 2);
                                string lower = name.ToLowerInvariant();
                                foreach (string e in exts)
                                {
                                    if (lower.EndsWith(e)) { result.Add(ts.ToString() + "|" + reason.ToString() + "|" + name); break; }
                                }
                            }
                        }
                        off += len;
                    }
                    if (nextUsn <= startUsn || result.Count > 5000) break;
                    startUsn = nextUsn;
                }
            }
            finally { Marshal.FreeHGlobal(input); Marshal.FreeHGlobal(buf); }
        }
        finally { h.Dispose(); }
        return result;
    }

    // Datei-Analyse: Entropie, PE-Sektionen, .NET und gesuchte Zeichenketten (ASCII und UTF-16)
    public static string PeInfo(string path, int maxBytes, string[] needles)
    {
        byte[] data;
        using (System.IO.FileStream fs = new System.IO.FileStream(path, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.ReadWrite | System.IO.FileShare.Delete))
        {
            int n = (int)Math.Min(fs.Length, (long)maxBytes);
            data = new byte[n];
            int read = 0;
            while (read < n)
            {
                int r = fs.Read(data, read, n - read);
                if (r <= 0) break;
                read += r;
            }
            if (read < n) Array.Resize(ref data, read);
        }
        long[] counts = new long[256];
        for (int i = 0; i < data.Length; i++) counts[data[i]]++;
        double ent = 0;
        if (data.Length > 0)
        {
            for (int i = 0; i < 256; i++)
            {
                if (counts[i] == 0) continue;
                double pr = (double)counts[i] / data.Length;
                ent -= pr * Math.Log(pr, 2);
            }
        }
        StringBuilder sections = new StringBuilder();
        bool net = false;
        if (data.Length > 0x40 && data[0] == 0x4D && data[1] == 0x5A)
        {
            int pe = BitConverter.ToInt32(data, 0x3C);
            if (pe > 0 && pe + 26 < data.Length && data[pe] == 0x50 && data[pe + 1] == 0x45)
            {
                int numSec = BitConverter.ToUInt16(data, pe + 6);
                int optSize = BitConverter.ToUInt16(data, pe + 20);
                int opt = pe + 24;
                int magic = BitConverter.ToUInt16(data, opt);
                int clr = (magic == 0x20B ? opt + 112 : opt + 96) + 14 * 8;
                if (clr + 8 <= data.Length && BitConverter.ToInt32(data, clr) != 0) net = true;
                int sec = opt + optSize;
                for (int k = 0; k < numSec && k < 96 && sec + 40 <= data.Length; k++)
                {
                    string name = Encoding.ASCII.GetString(data, sec, 8).TrimEnd('\0');
                    if (sections.Length > 0) sections.Append(',');
                    sections.Append(name.Replace("|", "").Replace(",", ""));
                    sec += 40;
                }
            }
        }
        string hay = Encoding.GetEncoding(28591).GetString(data);
        List<string> found = new List<string>();
        foreach (string nd in needles)
        {
            if (string.IsNullOrEmpty(nd)) continue;
            if (hay.IndexOf(nd, StringComparison.OrdinalIgnoreCase) >= 0) { found.Add(nd); continue; }
            StringBuilder wide = new StringBuilder();
            foreach (char c in nd) { wide.Append(c); wide.Append('\0'); }
            if (hay.IndexOf(wide.ToString(), StringComparison.OrdinalIgnoreCase) >= 0) found.Add(nd);
        }
        return ent.ToString("0.00", System.Globalization.CultureInfo.InvariantCulture) + "|" + sections.ToString() + "|" + (net ? "1" : "0") + "|" + string.Join(",", found.ToArray());
    }
}
