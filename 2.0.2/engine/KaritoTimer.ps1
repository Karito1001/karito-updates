<#
  Karito Tweaks - Timer-Auflösung 2.0.0
  -Query            : aktuelle, gröbste und feinste Auflösung ausgeben (in 100-ns-Schritten)
  -Set 5000 -Parent : Auflösung setzen (5000 = 0,5 ms, 10000 = 1 ms) und halten, bis Karito beendet wird
  Windows hält eine angeforderte Timer-Auflösung nur, solange der anfordernde Prozess läuft.
#>
param([switch]$Query, [int]$Set = 0, [int]$Parent = 0)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
function Out1($o) { [Console]::Out.WriteLine(($o | ConvertTo-Json -Compress)); [Console]::Out.Flush() }
try {
  $src = @'
using System;
using System.Runtime.InteropServices;
public static class KaritoTimerRes {
    [DllImport("ntdll.dll")] public static extern int NtQueryTimerResolution(out uint coarsest, out uint finest, out uint current);
    [DllImport("ntdll.dll")] public static extern int NtSetTimerResolution(uint desired, [MarshalAs(UnmanagedType.U1)] bool set, out uint current);
}
'@
  if (-not ('KaritoTimerRes' -as [type])) { Add-Type -TypeDefinition $src -Language CSharp | Out-Null }
  $lo = [uint32]0; $hi = [uint32]0; $cu = [uint32]0
  [void][KaritoTimerRes]::NtQueryTimerResolution([ref]$lo, [ref]$hi, [ref]$cu)
  if ($Query -or $Set -le 0) { Out1 @{ ok = $true; coarsest = $lo; finest = $hi; current = $cu }; exit 0 }
  $want = [uint32]([math]::Max($Set, [int]$hi))
  $now = [uint32]0
  $rc = [KaritoTimerRes]::NtSetTimerResolution($want, $true, [ref]$now)
  if ($rc -ne 0) { Out1 @{ ok = $false; msg = ('Windows hat die Timer-Auflösung abgelehnt (Code 0x{0:X8}).' -f $rc) }; exit 1 }
  Out1 @{ ok = $true; coarsest = $lo; finest = $hi; current = $now; set = $want }
  # halten, bis Karito beendet wird – prüft einmal pro Sekunde, kostet praktisch keine Leistung
  while ($true) {
    Start-Sleep -Seconds 1
    if ($Parent -gt 0 -and -not (Get-Process -Id $Parent -ErrorAction SilentlyContinue)) { break }
  }
  [void][KaritoTimerRes]::NtSetTimerResolution($want, $false, [ref]$now)
} catch {
  Out1 @{ ok = $false; msg = ('Timer-Auflösung: ' + $_.Exception.Message) }
  exit 1
}
