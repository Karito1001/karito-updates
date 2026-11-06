<#
  Karito Tweaks - Eingabe live setzen 2.0.0
  -Get                                   : aktuelle Werte lesen
  -KbDelay 0..3 -KbSpeed 0..31 -MouseSpeed 1..20 : sofort setzen und dauerhaft speichern
  Getrennte Datei wie Timer und Scanner: Fehlt sie, speichert die Engine die Werte für die nächste Anmeldung.
#>
param([switch]$Get, [int]$KbDelay = -1, [int]$KbSpeed = -1, [int]$MouseSpeed = -1)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
function Out1($o) { [Console]::Out.WriteLine(($o | ConvertTo-Json -Compress)); [Console]::Out.Flush() }
try {
  $src = @'
using System;
using System.Runtime.InteropServices;
public static class KaritoSpi {
    [DllImport("user32.dll", SetLastError = true)] static extern bool SystemParametersInfo(uint action, uint uParam, ref int pv, uint ini);
    [DllImport("user32.dll", EntryPoint = "SystemParametersInfo", SetLastError = true)] static extern bool SpiPtr(uint action, uint uParam, IntPtr pv, uint ini);
    public static int GetInt(uint action) { int v = 0; SystemParametersInfo(action, 0, ref v, 0); return v; }
    public static bool SetU(uint action, uint value) { return SpiPtr(action, value, IntPtr.Zero, 3); }
    public static bool SetP(uint action, int value) { return SpiPtr(action, 0, new IntPtr(value), 3); }
}
'@
  if (-not ('KaritoSpi' -as [type])) { Add-Type -TypeDefinition $src -Language CSharp | Out-Null }
  if (-not $Get) {
    # 3 = in die Benutzer-Einstellungen schreiben und alle Programme benachrichtigen
    if ($KbDelay -ge 0) { if ($KbDelay -gt 3) { throw 'Tastatur-Verzögerung: 0 bis 3.' }; [void][KaritoSpi]::SetU(0x0017, [uint32]$KbDelay) }
    if ($KbSpeed -ge 0) { if ($KbSpeed -gt 31) { throw 'Wiederholrate: 0 bis 31.' }; [void][KaritoSpi]::SetU(0x000B, [uint32]$KbSpeed) }
    if ($MouseSpeed -ge 0) { if ($MouseSpeed -lt 1 -or $MouseSpeed -gt 20) { throw 'Mausgeschwindigkeit: 1 bis 20.' }; [void][KaritoSpi]::SetP(0x0071, $MouseSpeed) }
  }
  Out1 @{ ok = $true; live = $true; delay = [KaritoSpi]::GetInt(0x0016); speed = [KaritoSpi]::GetInt(0x000A); mouse = [KaritoSpi]::GetInt(0x0070) }
} catch {
  Out1 @{ ok = $false; msg = ('Eingabe: ' + $_.Exception.Message) }
  exit 1
}
