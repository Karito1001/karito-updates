<#
  Karito Tweaks - Live-Messung 2.0.0
  Gibt jede Sekunde eine JSON-Zeile aus: CPU, GPU, RAM, DPC-/Interrupt-Zeit, Prozesse, Ping, Jitter, Paketverlust
  und ob das Spiel läuft. Nutzt WMI-Klassen statt Leistungsindikator-Namen, weil diese je nach Windows-Sprache anders heißen.
  -Parent <PID>      beendet sich, sobald Karito endet
  -Target <Adresse>  Ping-Ziel (Standard 1.1.1.1)
  -Game <Name>       Prozessname des Spiels ohne .exe, Platzhalter * erlaubt (z. B. FiveM_*GTAProcess)
  -CheckSig <Datei>  prüft nur die digitale Signatur einer Datei und gibt sie aus
#>
param([int]$Parent = 0, [string]$Target = '1.1.1.1', [string]$Game = '', [string]$CheckSig = '')
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
function Out1($o) { [Console]::Out.WriteLine(($o | ConvertTo-Json -Compress -Depth 4)); [Console]::Out.Flush() }
if ($CheckSig) {
  $sig = Get-AuthenticodeSignature -LiteralPath $CheckSig
  $sub = ''; if ($sig -and $sig.SignerCertificate) { $sub = [string]$sig.SignerCertificate.Subject }
  Out1 @{ ok = $true; status = [string]$sig.Status; subject = $sub }
  exit 0
}
$pinger = New-Object System.Net.NetworkInformation.Ping
$window = New-Object System.Collections.Generic.Queue[int]
$prev = -1; $jit = 0.0; $gpu = $null; $n = 0
while ($true) {
  $t0 = [DateTime]::UtcNow
  if ($Parent -gt 0 -and -not (Get-Process -Id $Parent -ErrorAction SilentlyContinue)) { break }
  $cpu = $null; $dpc = $null; $isr = $null
  $pr = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'"
  if ($pr) { $cpu = [int]$pr.PercentProcessorTime; $dpc = [math]::Round([double]$pr.PercentDPCTime, 2); $isr = [math]::Round([double]$pr.PercentInterruptTime, 2) }
  $ram = $null
  $os = Get-CimInstance -ClassName Win32_OperatingSystem
  if ($os -and $os.TotalVisibleMemorySize) { $ram = [int][math]::Round(100 - 100 * [double]$os.FreePhysicalMemory / [double]$os.TotalVisibleMemorySize) }
  if ($n % 2 -eq 0) {
    $eng = @(Get-CimInstance -ClassName Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine | Where-Object { $_.Name -like '*engtype_3D' })
    if ($eng.Count) { $sum = 0.0; foreach ($en in $eng) { $sum += [double]$en.UtilizationPercentage }; $gpu = [int][math]::Min(100, [math]::Round($sum)) }
  }
  $ping = $null
  try {
    $rep = $pinger.Send($Target, 1000)
    if ([string]$rep.Status -eq 'Success') { $ping = [int]$rep.RoundtripTime; if ($prev -ge 0) { $jit = 0.8 * $jit + 0.2 * [math]::Abs($ping - $prev) }; $prev = $ping; $window.Enqueue(0) } else { $window.Enqueue(1) }
  } catch { $window.Enqueue(1) }
  while ($window.Count -gt 30) { [void]$window.Dequeue() }
  $lostN = 0; foreach ($w in $window) { $lostN += $w }
  $loss = 0.0; if ($window.Count) { $loss = [math]::Round(100.0 * $lostN / $window.Count, 1) }
  $g = $null
  if ($Game) {
    $gp = @(Get-Process -Name $Game -ErrorAction SilentlyContinue | Sort-Object -Property WorkingSet64 -Descending)
    if ($gp.Count) { $g = @{ pid = $gp[0].Id; name = $gp[0].ProcessName + '.exe' } }
  }
  Out1 @{ cpu = $cpu; dpc = $dpc; isr = $isr; ram = $ram; gpu = $gpu; procs = @(Get-Process).Count; ping = $ping; jitter = [math]::Round($jit, 1); loss = $loss; game = $g }
  $n++
  $ms = 1000 - [int]([DateTime]::UtcNow - $t0).TotalMilliseconds
  if ($ms -gt 20) { Start-Sleep -Milliseconds $ms }
}
