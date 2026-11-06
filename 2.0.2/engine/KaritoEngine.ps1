#Requires -Version 5.1
<#
  Karito Tweaks - Engine 2.0.0
  Wird von der App aufgerufen, funktioniert aber auch direkt (als Administrator):
    .\KaritoEngine.ps1 -Command Test
    .\KaritoEngine.ps1 -Command List
    .\KaritoEngine.ps1 -Command Status
    .\KaritoEngine.ps1 -Command Apply  -Id gamedvr-off,mouse-accel-off [-WhatIf] [-AcceptRisk]
    .\KaritoEngine.ps1 -Command Revert -Id gamedvr-off
    .\KaritoEngine.ps1 -Command RevertAll
    .\KaritoEngine.ps1 -Command GameModeOn -Close cloud,windows,updater -PauseServices
    .\KaritoEngine.ps1 -Command GameModeOff
    .\KaritoEngine.ps1 -Command StartupList
    .\KaritoEngine.ps1 -Command StartupSet -Name Spotify -Scope HKCU [-Enable]
    .\KaritoEngine.ps1 -Command Hwid
  Mit -Json gibt die Engine genau ein JSON-Objekt aus: { ok, log:[{lvl,msg}], data }.

  Sicherheitsregeln (fest eingebaut, unabhaengig vom Katalog):
    - Die 8 geschuetzten Dienste werden nie veraendert, gestoppt oder deaktiviert.
    - Dienst-Tweaks aendern nur den Starttyp ausgewaehlter Dienste (nie der 8 geschuetzten).
      Der Gaming-Modus pausiert nur Dienste aus seiner Liste und startet sie wieder.
    - Vor jeder Aenderung wird der Originalwert gespeichert; Fehler werden zurueckgerollt.
    - Geloescht wird nur unter LOCALAPPDATA, TEMP und Windows\Temp.
    - Systemkritische Prozesse, Launcher, Discord und Anti-Cheat werden nie beendet.
#>
param(
  [ValidateSet('List','Test','Status','Apply','Revert','RevertAll','GameModeOn','GameModeOff','StartupList','StartupSet','Hwid','Scan','NetTest','Perf','Hardware','InputGet','InputSet')]
  [string]$Command = 'List',
  [string[]]$Id = @(),
  [string[]]$Close = @(),
  [string]$Name = '',
  [ValidateSet('HKCU','HKLM','HKLM32','FOLDERU','FOLDERM','TASK')][string]$Scope = 'HKCU',
  [switch]$Enable,
  [switch]$PauseServices,
  [switch]$WhatIf,
  [switch]$AcceptRisk,
  [ValidateSet('Health','Integrity','Fortnite')][string]$Mode = 'Health',
  [switch]$Save,
  [string[]]$Strings = @(),
  [int]$KbDelay = -1,
  [int]$KbSpeed = -1,
  [int]$MouseSpeed = -1,
  [switch]$Json
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false } catch {}

$Version = '2.0.0'
# Bei Aufruf per -File kommen Listen als "a,b,c" an.
$Id    = @($Id    | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$Close = @($Close | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$Strings = @($Strings | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ -match '^[a-z0-9._\- ]{3,40}$' })

$Protected = [ordered]@{
  'SysMain'   = 'SysMain'
  'DNSCache'  = 'DNS Client'
  'DusmSvc'   = 'Datennutzung'
  'DPS'       = 'Diagnoserichtliniendienst'
  'EventLog'  = 'Windows-Ereignisprotokoll'
  'PcaSvc'    = 'Programmkompatibilitäts-Assistent'
  'DiagTrack' = 'Benutzererfahrungen und Telemetrie'
  'CDPSvc'    = 'Plattformdienst für verbundene Geräte'
}
$ProtNames = @($Protected.Keys)
# Dienste-Check: Diese Dienste prüfen viele FiveM-Server im PC-Check. def = Windows-Standard (2 automatisch, 3 manuell),
# dl = verzögerter Start, lock = Grund, warum Karito den Dienst nicht ausschaltet (leer = darf aus). Tweaks fassen sie nie an.
$PcSvc = [ordered]@{
  'SysMain'   = @{ label = 'SysMain (Prefetch)'; def = 2; dl = 0; lock = '' }
  'DNSCache'  = @{ label = 'DNS-Client'; def = 2; dl = 0; lock = 'Windows lässt den DNS-Client nicht beenden.' }
  'DusmSvc'   = @{ label = 'Datennutzung'; def = 2; dl = 0; lock = '' }
  'WinDefend' = @{ label = 'Microsoft Defender Antivirus'; def = 2; dl = 0; lock = 'Defender schaltest du in der Windows-Sicherheit – Karito ändert ihn nicht.' }
  'DPS'       = @{ label = 'Diagnoserichtliniendienst'; def = 2; dl = 0; lock = '' }
  'Appinfo'   = @{ label = 'Anwendungsinformationen (Adminrechte)'; def = 3; dl = 0; lock = 'Ohne ihn fragt Windows nicht mehr nach Adminrechten – auch Karito startet dann nicht mehr.' }
  'BFE'       = @{ label = 'Basisfiltermodul (Firewall)'; def = 2; dl = 0; lock = 'Ohne ihn funktionieren Firewall und Teile des Netzwerks nicht.' }
  'EventLog'  = @{ label = 'Windows-Ereignisprotokoll'; def = 2; dl = 0; lock = 'Windows braucht das Ereignisprotokoll für viele andere Dienste.' }
  'PcaSvc'    = @{ label = 'Programmkompatibilitäts-Assistent'; def = 2; dl = 0; lock = '' }
  'DiagTrack' = @{ label = 'Benutzererfahrungen und Telemetrie'; def = 2; dl = 0; lock = '' }
  'CDPSvc'    = @{ label = 'Plattform für verbundene Geräte'; def = 2; dl = 1; lock = '' }
  'Schedule'  = @{ label = 'Aufgabenplanung'; def = 2; dl = 0; lock = 'Windows lässt die Aufgabenplanung nicht beenden.' }
}
$Never = @('csrss','winlogon','wininit','services','lsass','svchost','smss','explorer','dwm','system','idle','registry',
  'fontdrvhost','sihost','ctfmon','audiodg','MsMpEng','SecurityHealthService','SecurityHealthSystray','Discord','Steam',
  'steamwebhelper','EpicGamesLauncher','EpicWebHelper','Battle.net','Agent','RiotClientServices','RiotClientUx','vgc','vgtray',
  'UbisoftConnect','upc','FiveM','obs64','powershell','pwsh','Karito Tweaks')
$AllowedTypes = @('reg','svc','qos','regkv','plan','pwr','del','nic','dns','dnsflush','ifeo','gpupref','ini','xml','layers','mmagent','hiber')
$Guid = '[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}'

$Cat = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $PSScriptRoot 'tweaks.json') | ConvertFrom-Json
$Tweaks = @($Cat.tweaks)
$Dir = Join-Path $env:ProgramData 'KaritoTweaks'
$StateFile = Join-Path $Dir 'state.json'

$Log = New-Object System.Collections.ArrayList
$Data = $null
$script:Freed = 0
$script:PlanChanged = $false

# ---------------------------------------------------------------- Hilfsfunktionen
function Say($m, $l = 'info') {
  [void]$Log.Add(@{ lvl = $l; msg = [string]$m })
  if (-not $Json) {
    $c = @{ info = 'Gray'; ok = 'Green'; warn = 'Yellow'; err = 'Red' }[$l]
    Write-Host $m -ForegroundColor $c
  }
}

# Fortschritt für die App: "@@P|erledigt/gesamt|Text" bzw. "@@P|prep|Text" (nur im JSON-Modus)
$script:StepI = 0; $script:StepN = 0; $script:StepOn = $false; $script:StepAct = 0
function Step($label, [switch]$Prep) {
  if (-not $Json) { return }
  $k = "$($script:StepI)/$($script:StepN)"; if ($Prep) { $k = 'prep' }
  # keine geschweiften Klammern und kein | im Text: die App liest danach das JSON-Ergebnis
  $lt = ([string]$label).Replace('|', '/').Replace('{', '(').Replace('}', ')')
  try { [Console]::Out.WriteLine('@@P|' + $k + '|' + $lt); [Console]::Out.Flush() } catch {}
}
function IsAdmin {
  ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function NeedAdmin { if (-not (IsAdmin)) { throw 'Bitte Karito Tweaks als Administrator starten.' } }
function Dw($v) { $n = [int64]$v; if ($n -gt [int]::MaxValue) { $n -= 4294967296 }; [int]$n }
function GetT($i) { foreach ($t in $Tweaks) { if ($t.id -eq $i) { return $t } }; throw "Unbekannter Tweak: $i" }
function HasT($i) { foreach ($t in $Tweaks) { if ($t.id -eq $i) { return $true } }; $false }
function Idx($i) { for ($k = 0; $k -lt $Tweaks.Count; $k++) { if ($Tweaks[$k].id -eq $i) { return $k } }; 9999 }

function LoadState {
  $h = @{}
  if (Test-Path -LiteralPath $StateFile) {
    try {
      $o = Get-Content -Raw -Encoding UTF8 -LiteralPath $StateFile | ConvertFrom-Json
      if ($o) { $o.PSObject.Properties | ForEach-Object { $h[$_.Name] = $_.Value } }
    } catch { Say 'Statusdatei war beschädigt und wird neu angelegt.' 'warn' }
  }
  $h
}
function SaveState($h) {
  New-Item -ItemType Directory -Force -Path $Dir | Out-Null
  $tmp = "$StateFile.tmp"
  ($h | ConvertTo-Json -Depth 12) | Set-Content -Encoding UTF8 -LiteralPath $tmp
  Move-Item -LiteralPath $tmp -Destination $StateFile -Force
}
function SnapModes {
  ($ProtNames | ForEach-Object {
    $s = Get-CimInstance Win32_Service -Filter "Name='$_'" -ErrorAction SilentlyContinue
    if ($s) { "$_=$($s.StartMode)" } else { "$_=n/a" }
  }) -join ';'
}
function ExpandIds($ids) {
  $o = New-Object System.Collections.ArrayList
  foreach ($i in $ids) {
    $t = GetT $i
    if ($t.includes) { foreach ($j in (ExpandIds @($t.includes))) { if (-not $o.Contains($j)) { [void]$o.Add($j) } } }
    if ($t.actions -and -not $o.Contains($i)) { [void]$o.Add($i) }
  }
  , @($o | Sort-Object { Idx $_ })
}

# ---------------------------------------------------------------- Schutzregeln
function Guard($t) {
  # Pakete (includes) haben keine eigenen Aktionen. @($null) wäre in PowerShell 1 leeres Element – daher filtern.
  foreach ($a in @($t.actions | Where-Object { $null -ne $_ })) {
    if ($AllowedTypes -notcontains $a.type) { throw "BLOCKIERT: Aktionstyp '$($a.type)' in $($t.id)" }
    if ($a.type -in 'reg', 'regkv') {
      foreach ($p in $ProtNames) {
        if ($a.path -match ('(?i)\\Services\\' + [regex]::Escape($p) + '(\\|$)')) { throw "BLOCKIERT: $($t.id) berührt den geschützten Dienst $p" }
      }
    }
    if ($a.type -eq 'svc' -and $ProtNames -contains [string]$a.name) { throw "BLOCKIERT: $($t.id) berührt den geschützten Dienst $($a.name)" }
    if ($a.type -eq 'del') {
      foreach ($p in @($a.paths | Where-Object { $_ })) {
        $x = [Environment]::ExpandEnvironmentVariables($p).TrimEnd('\')
        $allowed = $false
        foreach ($r in @($env:LOCALAPPDATA, $env:TEMP, (Join-Path $env:SystemRoot 'Temp'))) {
          if ($r -and $x.StartsWith($r.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { $allowed = $true }
        }
        foreach ($r in @($env:TEMP, (Join-Path $env:SystemRoot 'Temp'))) {
          if ($r -and $a.contents -and ($x -ieq $r.TrimEnd('\'))) { $allowed = $true }
        }
        if (-not $allowed -or $x -match '\.\.') { throw "BLOCKIERT: Pfad nicht erlaubt: $x" }
      }
    }
    if ($a.type -eq 'ifeo') {
      foreach ($e in @($a.exes | Where-Object { $_ })) { if ($e -notmatch '^[\w.\- ]+\.exe$') { throw "BLOCKIERT: ungültiger Prozessname $e" } }
    }
    if ($a.type -eq 'pwr') {
      if (($a.sub -notmatch "^$Guid$") -or ($a.set -notmatch "^$Guid$")) { throw "BLOCKIERT: ungültige Energie-GUID in $($t.id)" }
    }
    if ($a.type -in 'ini', 'xml') {
      $x = [Environment]::ExpandEnvironmentVariables([string]$a.path)
      $allowed = $false
      foreach ($r in @($env:LOCALAPPDATA, $env:APPDATA)) {
        if ($r -and $x.StartsWith($r.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { $allowed = $true }
      }
      if (-not $allowed -or $x -match '\.\.') { throw "BLOCKIERT: Konfigurationsdatei nicht erlaubt: $x" }
      if (-not $a.sets) { throw "BLOCKIERT: $($t.id) hat keine Einstellungen" }
    }
    if ($a.type -eq 'layers') {
      foreach ($fl in @($a.flags | Where-Object { $_ })) { if ([string]$fl -notmatch '^[A-Z0-9_]+$') { throw "BLOCKIERT: ungültiges Kompatibilitäts-Flag $fl" } }
    }
  }
}

# ---------------------------------------------------------------- Registry
function FirstMissing($p) {
  # Höchster noch fehlender Schlüssel. Bewusst ohne Split-Path: "-LiteralPath -Parent" gibt es in PowerShell 5.1 nicht.
  $m = $null; $cur = [string]$p
  while ($cur -and -not (Test-Path -LiteralPath $cur)) {
    $m = $cur
    $ix = $cur.LastIndexOf('\')
    if ($ix -le 0) { break }
    $cur = $cur.Substring(0, $ix)
  }
  $m
}
function RegUndo($p, $n) {
  $u = @{ t = 'reg'; path = $p; name = $n; had = $false; mk = (FirstMissing $p) }
  if (-not $u.mk) {
    $k = Get-Item -LiteralPath $p
    $vn = $n; if ($n -eq '(default)') { $vn = '' }
    if (@($k.GetValueNames()) -contains $vn) {
      $u.had = $true
      $u.kind = $k.GetValueKind($vn).ToString()
      $u.value = $k.GetValue($vn, $null, 'DoNotExpandEnvironmentNames')
    }
  }
  $u
}
function RegExePath($p) { (([string]$p) -replace '^Registry::', '' -replace '^HKEY_LOCAL_MACHINE', 'HKLM' -replace '^HKEY_CURRENT_USER', 'HKCU') -replace '^(HKLM|HKCU):\\?', '$1\' }
function RegExeSet($p, $n, $v, $k) {
  # Rückfallebene: reg.exe darf Werte schreiben, die Windows (z. B. UCPD) für PowerShell sperrt
  $ErrorActionPreference = 'Continue'
  $rt = @{ DWord = 'REG_DWORD'; QWord = 'REG_QWORD'; String = 'REG_SZ'; ExpandString = 'REG_EXPAND_SZ'; MultiString = 'REG_MULTI_SZ'; Binary = 'REG_BINARY' }[[string]$k]
  if (-not $rt) { $rt = 'REG_SZ' }
  $d = [string]$v
  if ($k -eq 'DWord' -or $k -eq 'QWord') { $dv = [int64]$v; if ($k -eq 'DWord' -and $dv -lt 0) { $dv += 4294967296 }; $d = [string]$dv }
  elseif ($k -eq 'MultiString') { $d = @($v) -join '\0' }
  elseif ($k -eq 'Binary') { $d = (@($v) | ForEach-Object { '{0:X2}' -f [int]$_ }) -join '' }
  $ra = @('add', (RegExePath $p), '/f')
  if ($n -eq '(default)') { $ra += '/ve' } else { $ra += @('/v', [string]$n) }
  $ra += @('/t', $rt)
  if ($d -ne '') { $ra += @('/d', $d) }
  $null = & (Join-Path $env:SystemRoot 'System32\reg.exe') @ra 2>&1
  if ($LASTEXITCODE -ne 0) { throw 'PROT:Windows schützt diese Einstellung' }
}
function RegExeDel($p, $n) {
  $ErrorActionPreference = 'Continue'
  $ra = @('delete', (RegExePath $p), '/f')
  if ($n) { if ($n -eq '(default)') { $ra += '/ve' } else { $ra += @('/v', [string]$n) } }
  $null = & (Join-Path $env:SystemRoot 'System32\reg.exe') @ra 2>&1
}
function ProtMsg($er) {
  # Erkennt, ob Windows eine Einstellung schützt (Zugriffsrechte, UCPD) – dann „teilweise“ statt Fehler
  $m = [string]$er.Exception.Message
  if ($m.StartsWith('PROT:')) { return $m.Substring(5) }
  if ($m.StartsWith('SKIP:')) { return $null }
  $ex = $er.Exception
  while ($ex) {
    if ($ex -is [System.Security.SecurityException] -or $ex -is [System.UnauthorizedAccessException]) { return 'Windows schützt diese Einstellung' }
    $ex = $ex.InnerException
  }
  if ($m -match 'Registrierungszugriff ist unzul|nicht autorisierten Vorgang|Requested registry access|unauthorized operation|Zugriff verweigert|Access is denied') { return 'Windows schützt diese Einstellung' }
  $null
}
function RegSet($p, $n, $v, $k) {
  try {
    if (-not (Test-Path -LiteralPath $p)) { New-Item -Path $p -Force | Out-Null }
    if ($n -eq '(default)') { Set-Item -LiteralPath $p -Value ([string]$v); return }
    $pv = $v
    switch ($k) {
      'DWord'       { $pv = Dw $v }
      'QWord'       { $pv = [int64]$v }
      'Binary'      { $pv = [byte[]]@($v) }
      'MultiString' { $pv = [string[]]@($v) }
    }
    New-ItemProperty -LiteralPath $p -Name $n -Value $pv -PropertyType $k -Force | Out-Null
  } catch {
    if (-not (ProtMsg $_)) { throw }
    RegExeSet $p $n $v $k
  }
}

# ---------------------------------------------------------------- Dienste (über den Windows-Dienst-Manager)
function SvcGetStart($sn) {
  $sp = Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $sn) -ErrorAction SilentlyContinue
  $st = 3; if ($sp -and $null -ne $sp.Start) { $st = [int]$sp.Start }
  $dl = 0; if ($sp -and $null -ne $sp.DelayedAutostart) { $dl = [int]$sp.DelayedAutostart }
  @{ start = $st; delayed = $dl }
}
function SvcSetStart($sn, $start, $delayed) {
  # 1. Dienst-Manager wie in services.msc  2. Registry  3. sonst schützt Windows den Dienst
  $ErrorActionPreference = 'Continue'
  $scMode = 'demand'
  switch ([int]$start) { 0 { $scMode = 'boot' } 1 { $scMode = 'system' } 2 { $scMode = 'auto'; if ([int]$delayed -eq 1) { $scMode = 'delayed-auto' } } 4 { $scMode = 'disabled' } }
  $so = & (Join-Path $env:SystemRoot 'System32\sc.exe') config $sn start= $scMode 2>&1 | Out-String
  $code = $LASTEXITCODE
  if ($code -eq 0) { return }
  $kp = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $sn
  try {
    Set-ItemProperty -LiteralPath $kp -Name Start -Value ([int]$start) -Type DWord -ErrorAction Stop
    if ([int]$start -eq 2) { Set-ItemProperty -LiteralPath $kp -Name DelayedAutostart -Value ([int]$delayed) -Type DWord -ErrorAction Stop }
    return
  } catch {}
  if ($code -eq 5) { throw 'PROT:Windows schützt diesen Dienst' }
  throw ('PROT:Dienst ' + $sn + ' ließ sich nicht umstellen (' + (($so -replace '\s+', ' ').Trim()) + ')')
}
function PcSvcList {
  $out = @()
  foreach ($n in $PcSvc.Keys) {
    $d = $PcSvc[$n]; $gs = Get-Service -Name $n -ErrorAction SilentlyContinue
    $state = 'missing'
    if ($gs) { $state = 'stopped'; $gst = [string]$gs.Status; if ($gst -eq 'Running') { $state = 'running' } elseif ($gst -like '*Pending') { $state = 'pending' } }
    $sg = SvcGetStart $n
    $start = 'manual'
    switch ([int]$sg.start) { 0 { $start = 'boot' } 1 { $start = 'system' } 2 { $start = 'auto' } 4 { $start = 'disabled' } }
    $out += @{ name = $n; label = $d.label; state = $state; start = $start; delayed = [int]$sg.delayed; def = [int]$d.def; lock = $d.lock }
  }
  $out
}
function PcSvcSet($n, [bool]$on) {
  $d = $PcSvc[$n]
  $gs = Get-Service -Name $n -ErrorAction SilentlyContinue
  if (-not $gs) { Say "$($d.label): auf diesem PC nicht vorhanden" 'warn'; return @{ name = $n; ok = $false } }
  if ($n -eq 'WinDefend') { Say "$($d.label): bitte in der Windows-Sicherheit einschalten – Karito ändert Defender nicht" 'warn'; return @{ name = $n; ok = $false } }
  try {
    if ($on) {
      $cur = SvcGetStart $n
      if ([int]$cur.start -ne [int]$d.def -or ([int]$d.def -eq 2 -and [int]$cur.delayed -ne [int]$d.dl)) { SvcSetStart $n $d.def $d.dl }
      if ([string]$gs.Status -ne 'Running') { Start-Service -Name $n -ErrorAction Stop }
      Say "$($d.label) läuft (Windows-Standard)" 'ok'
    } else {
      if ($d.lock) { Say "$($d.label): $($d.lock)" 'warn'; return @{ name = $n; ok = $false } }
      SvcSetStart $n 4 0
      if ([string]$gs.Status -ne 'Stopped') { Stop-Service -Name $n -Force -ErrorAction Stop }
      Say "$($d.label) ausgeschaltet – startet auch nach einem Neustart nicht mehr" 'ok'
    }
    return @{ name = $n; ok = $true }
  } catch {
    $m = [string]$_.Exception.Message; if ($m -like 'PROT:*') { $m = $m.Substring(5) }
    Say "$($d.label): $m" 'err'
    return @{ name = $n; ok = $false }
  }
}
function IsEmptyTree($p) {
  $k = Get-Item -LiteralPath $p -ErrorAction SilentlyContinue
  if (-not $k) { return $true }
  if ($k.ValueCount -gt 0) { return $false }
  foreach ($c in @(Get-ChildItem -LiteralPath $p -ErrorAction SilentlyContinue)) { if (-not (IsEmptyTree $c.PSPath)) { return $false } }
  $true
}
function KvSet($p, $n, $key, $val, $undo) {
  $cur = ''
  if ($undo.had) { $cur = [string]$undo.value }
  $parts = @($cur -split ';' | Where-Object { $_ -and ($_ -notlike ($key + '=*')) })
  $parts += ($key + '=' + $val)
  RegSet $p $n (($parts -join ';') + ';') 'String'
}

# ---------------------------------------------------------------- Energie
function ActiveScheme { [regex]::Match((powercfg /getactivescheme | Out-String), $Guid).Value }
function PwrGet($scheme, $sub, $set) {
  # /qh zeigt auch versteckte Optionen (Kern-Parking, CPU-Leerlauf, Boost-Modus, AHCI-Link …) – /query nicht
  $ErrorActionPreference = 'Continue'
  $o = powercfg /qh $scheme $sub $set | Out-String
  $m = [regex]::Matches($o, '0x[0-9a-fA-F]{8}')
  if ($LASTEXITCODE -eq 0 -and $m.Count -ge 2) { return [Convert]::ToInt32($m[$m.Count - 2].Value, 16) }
  # Rückfall: Wert direkt aus der Registry – erst der eigene Wert des Plans, dann der Windows-Standard
  $base = 'HKLM:\SYSTEM\CurrentControlSet\Control\Power'
  foreach ($rk in @("$base\User\PowerSchemes\$scheme\$sub\$set", "$base\PowerSettings\$sub\$set\DefaultPowerSchemeValues\$scheme")) {
    $rv = (Get-ItemProperty -LiteralPath $rk -Name ACSettingIndex -ErrorAction SilentlyContinue).ACSettingIndex
    if ($null -ne $rv) { return [int]$rv }
  }
  if (-not (Test-Path -LiteralPath "$base\PowerSettings\$sub\$set")) { throw 'SKIP:Diese Energieoption gibt es auf deinem PC nicht' }
  throw 'SKIP:Energieoption konnte nicht gelesen werden'
}

# ---------------------------------------------------------------- Dateien
function DirSize($p) {
  try {
    $s = (Get-ChildItem -LiteralPath $p -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
    if ($s) { [int64]$s } else { [int64]0 }
  } catch { [int64]0 }
}
function ClearItem($item) {
  try {
    if ($item.PSIsContainer) { [System.IO.Directory]::Delete($item.FullName, $true) }   # folgt keinen Verknüpfungen
    else { Remove-Item -LiteralPath $item.FullName -Force -ErrorAction Stop }
  } catch {}
}
function FixedDrives { , @([System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady } | ForEach-Object { $_.Name.Substring(0, 2) }) }
function ExeTargets($list) {
  $r = New-Object System.Collections.ArrayList
  $drives = FixedDrives
  foreach ($p in @($list)) {
    $x = [Environment]::ExpandEnvironmentVariables($p)
    $cands = @()
    if ($x.StartsWith('*:')) { foreach ($d in $drives) { $cands += ($d + $x.Substring(2)) } } else { $cands = @($x) }
    foreach ($c in $cands) {
      if ($c -match '[*?]') {
        foreach ($f in @(Get-Item -Path $c -ErrorAction SilentlyContinue)) { if (-not $r.Contains($f.FullName)) { [void]$r.Add($f.FullName) } }
      } elseif (Test-Path -LiteralPath $c -PathType Leaf) {
        $f = (Get-Item -LiteralPath $c).FullName
        if (-not $r.Contains($f)) { [void]$r.Add($f) }
      }
    }
  }
  , @($r)
}

# ---------------------------------------------------------------- Spiel-Konfigurationen (INI / XML)
function ReadText($p) {
  $bytes = [System.IO.File]::ReadAllBytes($p)
  $enc = New-Object System.Text.UTF8Encoding $false
  $off = 0
  if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) { $enc = New-Object System.Text.UnicodeEncoding $false, $true; $off = 2 }
  elseif ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { $enc = New-Object System.Text.UTF8Encoding $true; $off = 3 }
  @{ text = $enc.GetString($bytes, $off, $bytes.Length - $off); enc = $enc }
}
function WriteText($p, $txt, $enc) { [System.IO.File]::WriteAllText($p, $txt, $enc) }
function IniFind($lines, $section) {
  $sec = -1; $end = $lines.Count
  for ($i = 0; $i -lt $lines.Count; $i++) {
    $tl = ([string]$lines[$i]).Trim()
    if ($tl.StartsWith('[') -and $tl.EndsWith(']')) {
      if ($sec -ge 0) { $end = $i; break }
      if ($tl.Substring(1, $tl.Length - 2) -ieq $section) { $sec = $i }
    }
  }
  @{ sec = $sec; end = $end }
}
function IniSet($txt, $section, $key, $value) {
  $nl = "`n"; if ($txt -match "`r`n") { $nl = "`r`n" }
  $lines = New-Object System.Collections.ArrayList
  foreach ($ln in ($txt -split "`r?`n")) { [void]$lines.Add($ln) }
  $f = IniFind $lines $section
  $had = $false; $old = $null
  if ($f.sec -lt 0) {
    $ins = $lines.Count
    if ($ins -gt 0 -and $lines[$ins - 1] -eq '') { $ins-- }
    $lines.Insert($ins, "[$section]"); $lines.Insert($ins + 1, "$key=$value")
  } else {
    $pos = -1
    for ($i = $f.sec + 1; $i -lt $f.end; $i++) {
      $m = [regex]::Match([string]$lines[$i], '^\s*([^=;#]+?)\s*=(.*)$')
      if ($m.Success -and $m.Groups[1].Value -ieq $key) { $pos = $i; $had = $true; $old = $m.Groups[2].Value; break }
    }
    if ($pos -ge 0) { $lines[$pos] = "$key=$value" }
    else {
      $ins = $f.end
      while ($ins -gt $f.sec + 1 -and ([string]$lines[$ins - 1]).Trim() -eq '') { $ins-- }
      $lines.Insert($ins, "$key=$value")
    }
  }
  @{ text = ($lines -join $nl); had = $had; old = $old }
}
function IniRemove($txt, $section, $key) {
  $nl = "`n"; if ($txt -match "`r`n") { $nl = "`r`n" }
  $lines = New-Object System.Collections.ArrayList
  foreach ($ln in ($txt -split "`r?`n")) { [void]$lines.Add($ln) }
  $f = IniFind $lines $section
  if ($f.sec -ge 0) {
    for ($i = $f.end - 1; $i -gt $f.sec; $i--) {
      $m = [regex]::Match([string]$lines[$i], '^\s*([^=;#]+?)\s*=(.*)$')
      if ($m.Success -and $m.Groups[1].Value -ieq $key) { $lines.RemoveAt($i) }
    }
  }
  $lines -join $nl
}
function LoadXml($p) { $d = New-Object System.Xml.XmlDocument; $d.PreserveWhitespace = $true; $d.Load($p); $d }
function SaveXml($d, $p) {
  $b = [System.IO.File]::ReadAllBytes($p)
  $bom = ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF)
  $ws = New-Object System.Xml.XmlWriterSettings
  $ws.Encoding = New-Object System.Text.UTF8Encoding $bom
  $w = [System.Xml.XmlWriter]::Create($p, $ws)
  try { $d.Save($w) } finally { $w.Close() }
}

# ---------------------------------------------------------------- Rueckgaengig
function Undo($e) {
  switch ($e.t) {
    'reg' {
      if ($e.had) { RegSet $e.path $e.name $e.value $e.kind }
      else {
        if (Test-Path -LiteralPath $e.path) { try { Remove-ItemProperty -LiteralPath $e.path -Name $e.name -ErrorAction Stop } catch { if (ProtMsg $_) { RegExeDel $e.path $e.name } } }
        if ($e.mk -and (Test-Path -LiteralPath $e.mk) -and (($e.name -eq '(default)') -or (IsEmptyTree $e.mk))) { try { Remove-Item -LiteralPath $e.mk -Recurse -Force -ErrorAction Stop } catch { if (ProtMsg $_) { RegExeDel $e.mk $null } } }
      }
    }
    'svc' { SvcSetStart $e.name ([int]$e.start) ([int]$e.delayed) }
    'qos' { Get-NetQosPolicy -Name $e.name -ErrorAction SilentlyContinue | Remove-NetQosPolicy -Confirm:$false -ErrorAction SilentlyContinue }
    'plan' {
      if ($e.old) { powercfg /setactive $e.old | Out-Null }
      if ($e.new) { powercfg /delete $e.new | Out-Null }
    }
    'pwr' {
      powercfg /setacvalueindex $e.scheme $e.sub $e.set $e.old | Out-Null
      if ((ActiveScheme) -eq $e.scheme) { powercfg /setactive $e.scheme | Out-Null }
    }
    'nic' { $old = @($e.old | Where-Object { $null -ne $_ }); if ($old.Count) { Set-NetAdapterAdvancedProperty -Name $e.adapter -RegistryKeyword $e.kw -RegistryValue $old -ErrorAction SilentlyContinue } }
    'dns' {
      $old = @($e.old | Where-Object { $_ })
      if ($old.Count -eq 0) { Set-DnsClientServerAddress -InterfaceIndex $e.idx -ResetServerAddresses -ErrorAction SilentlyContinue }
      else { Set-DnsClientServerAddress -InterfaceIndex $e.idx -ServerAddresses $old -ErrorAction SilentlyContinue }
      Clear-DnsClientCache -ErrorAction SilentlyContinue
    }
    'ini' {
      if (Test-Path -LiteralPath $e.path) {
        $f = ReadText $e.path
        if ($e.had) { $nt = (IniSet $f.text $e.section $e.key ([string]$e.old)).text } else { $nt = IniRemove $f.text $e.section $e.key }
        WriteText $e.path $nt $f.enc
      }
    }
    'xml' {
      if (Test-Path -LiteralPath $e.path) {
        $doc = LoadXml $e.path
        $node = $doc.SelectSingleNode('//' + $e.parent + '/' + $e.name)
        if ($node) { $node.SetAttribute('value', [string]$e.old); SaveXml $doc $e.path }
      }
    }
    'hiber' { powercfg /hibernate on | Out-Null }
    'mmagent' { if ($e.was) { Enable-MMAgent -MemoryCompression -ErrorAction SilentlyContinue } else { Disable-MMAgent -MemoryCompression -ErrorAction SilentlyContinue } }
  }
}

# ---------------------------------------------------------------- Anwenden
function DoApply($t) {
  $u = New-Object System.Collections.ArrayList
  $script:Freed = 0
  $script:ProtParts = New-Object System.Collections.ArrayList
  try {
    foreach ($a in @($t.actions | Where-Object { $null -ne $_ })) {
      if ($script:StepOn) { if ($script:StepAct -gt 0) { $script:StepI++; Step "Wird angewendet: $($t.name)" }; $script:StepAct++ }
      try {
      switch ($a.type) {
        'reg' {
          $tg = @($a.path)
          if ($a.path -match '\*') { $tg = @(Get-Item -Path $a.path -ErrorAction SilentlyContinue | ForEach-Object { $_.PSPath }) }
          if ($tg.Count -eq 0) { throw 'SKIP:Keine passenden Einträge auf diesem PC' }
          foreach ($p in $tg) {
            if ($a.ifExists -and -not (Test-Path -LiteralPath $p)) { continue }   # z. B. Dienst nicht installiert
            [void]$u.Add((RegUndo $p $a.name)); if (-not $WhatIf) { RegSet $p $a.name $a.value $a.kind }
          }
        }
        'svc' {
          $sn = [string]$a.name
          if (Test-Path -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $sn)) {
            $want = 3; switch ([string]$a.start) { 'disabled' { $want = 4 } 'manual' { $want = 3 } 'auto' { $want = 2 } }
            $old = SvcGetStart $sn
            if (-not $WhatIf -and $old.start -ne $want) { SvcSetStart $sn $want 0 }
            [void]$u.Add(@{ t = 'svc'; name = $sn; start = $old.start; delayed = $old.delayed })
          }
        }
        'qos' {
          # Netzwerk-Vorrang (DSCP) für ein Spiel – wirkt, wenn Router oder Netz QoS beachten
          if (-not (Get-Command New-NetQosPolicy -ErrorAction SilentlyContinue)) { throw 'SKIP:Netzwerk-QoS ist auf diesem PC nicht verfügbar' }
          # Ohne diesen Wert gelten QoS-Regeln nur in Firmen-Domänen. Harmlos, darum ohne Rückgängig-Eintrag.
          if (-not $WhatIf) { try { RegSet 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS' 'Do not use NLA' '1' 'String' } catch {} }
          $qi = 0
          foreach ($qx in @($a.exes | Where-Object { $_ })) {
            $qi++; $qn = 'Karito ' + [string]$a.name + ' ' + $qi
            if (-not $WhatIf) {
              Get-NetQosPolicy -Name $qn -ErrorAction SilentlyContinue | Remove-NetQosPolicy -Confirm:$false -ErrorAction SilentlyContinue
              New-NetQosPolicy -Name $qn -AppPathNameMatchCondition ([string]$qx) -DSCPAction ([int]$a.dscp) -NetworkProfile All -ErrorAction Stop | Out-Null
            }
            [void]$u.Add(@{ t = 'qos'; name = $qn })
          }
        }
        'regkv' {
          $e = RegUndo $a.path $a.name; [void]$u.Add($e)
          if (-not $WhatIf) { KvSet $a.path $a.name $a.key $a.val $e }
        }
        'ifeo' {
          foreach ($x in @($a.exes | Where-Object { $_ })) {
            $p = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$x\PerfOptions"
            [void]$u.Add((RegUndo $p 'CpuPriorityClass'))
            if (-not $WhatIf) { RegSet $p 'CpuPriorityClass' $a.cpu 'DWord' }
          }
        }
        'gpupref' {
          $ex = ExeTargets $a.exes
          if ($ex.Count -eq 0) { throw 'SKIP:Spiel nicht am Standard-Ort gefunden' }
          $p = 'HKCU:\Software\Microsoft\DirectX\UserGpuPreferences'
          foreach ($f in $ex) { $e = RegUndo $p $f; [void]$u.Add($e); if (-not $WhatIf) { KvSet $p $f 'GpuPreference' '2' $e } }
          Say "  $($ex.Count) Spieldatei(en) gefunden"
        }
        'plan' {
          if (-not $WhatIf) {
            $old = ActiveScheme
            $o = powercfg -duplicatescheme $a.guid | Out-String
            $new = [regex]::Match($o, $Guid).Value
            if ($LASTEXITCODE -ne 0 -or -not $new) { throw 'SKIP:Dieser Energieplan wird auf deinem PC nicht unterstützt (z. B. Modern Standby)' }
            [void]$u.Add(@{ t = 'plan'; old = $old; new = $new })
            powercfg /setactive $new | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Energieplan konnte nicht aktiviert werden.' }
            $script:PlanChanged = $true
          }
        }
        'pwr' {
          $s = ActiveScheme
          $old = PwrGet $s $a.sub $a.set
          if (-not $WhatIf) {
            powercfg /setacvalueindex $s $a.sub $a.set $a.value | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Energieoption konnte nicht gesetzt werden.' }
            [void]$u.Add(@{ t = 'pwr'; scheme = $s; sub = $a.sub; set = $a.set; old = $old })
            powercfg /setactive $s | Out-Null
          }
        }
        'del' {
          if ($a.notRunning -and @(Get-Process -Name $a.notRunning -ErrorAction SilentlyContinue).Count) {
            throw "$($a.notRunning -replace '\*','') läuft noch – bitte zuerst schließen."
          }
          foreach ($p in @($a.paths | Where-Object { $_ })) {
            $x = [Environment]::ExpandEnvironmentVariables($p)
            if (-not (Test-Path -LiteralPath $x)) { continue }
            $before = DirSize $x
            if ($WhatIf) { $script:Freed += $before; continue }
            if ($a.contents) { foreach ($it in @(Get-ChildItem -LiteralPath $x -Force -ErrorAction SilentlyContinue)) { ClearItem $it } }
            else { ClearItem (Get-Item -LiteralPath $x -Force) }
            $after = 0; if (Test-Path -LiteralPath $x) { $after = DirSize $x }
            $script:Freed += [math]::Max(0, $before - $after)
          }
        }
        'nic' {
          if (-not (Get-Command Get-NetAdapterAdvancedProperty -ErrorAction SilentlyContinue)) { throw 'SKIP:Netzwerk-Module fehlen' }
          $props = @()
          foreach ($ad in @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue)) {
            $props += @(Get-NetAdapterAdvancedProperty -Name $ad.Name -RegistryKeyword $a.kw -ErrorAction SilentlyContinue |
              Where-Object { (-not $_.ValidRegistryValues) -or (@($_.ValidRegistryValues) -contains [string]$a.value) })
          }
          if ($props.Count -eq 0 -and -not $a.optional) { throw 'SKIP:Dein Netzwerkadapter hat diese Einstellung nicht' }
          $nicOk = 0; $nicErr = ''
          foreach ($pr in $props) {
            # ein einzelner Adapter (z. B. WLAN, ausgeschaltet) darf den Tweak nicht für alle anderen kippen
            try {
              if (-not $WhatIf) { Set-NetAdapterAdvancedProperty -Name $pr.Name -RegistryKeyword $a.kw -RegistryValue ([string]$a.value) -ErrorAction Stop }
              [void]$u.Add(@{ t = 'nic'; adapter = $pr.Name; kw = $a.kw; old = @($pr.RegistryValue) }); $nicOk++
            } catch { $nicErr = [string]$_.Exception.Message }
          }
          if ($props.Count -and -not $nicOk -and -not $a.optional) { throw ('SKIP:Der Netzwerkadapter lässt diese Einstellung nicht zu (' + $nicErr + ')') }
        }
        'dns' {
          $ads = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })
          if ($ads.Count -eq 0) { throw 'Kein aktiver Netzwerkadapter gefunden.' }
          foreach ($ad in $ads) {
            $ns = (Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($ad.InterfaceGuid)" -Name NameServer -ErrorAction SilentlyContinue).NameServer
            $old = @(([string]$ns) -split '[ ,]' | Where-Object { $_ })
            if (-not $WhatIf) { Set-DnsClientServerAddress -InterfaceIndex $ad.ifIndex -ServerAddresses @($a.servers) }
            [void]$u.Add(@{ t = 'dns'; idx = $ad.ifIndex; old = $old })
          }
          if (-not $WhatIf) { Clear-DnsClientCache -ErrorAction SilentlyContinue }
        }
        'dnsflush' { if (-not $WhatIf) { Clear-DnsClientCache } }
        'ini' {
          if ($a.notRunning -and @(Get-Process -Name $a.notRunning -ErrorAction SilentlyContinue).Count) { throw "$($a.notRunning -replace '\*','') läuft noch – bitte zuerst schließen." }
          $x = [Environment]::ExpandEnvironmentVariables([string]$a.path)
          if (-not (Test-Path -LiteralPath $x -PathType Leaf)) { throw 'SKIP:Einstellungsdatei nicht gefunden – starte das Spiel einmal und schließe es wieder' }
          $f = ReadText $x
          $txt = $f.text
          foreach ($kv in @($a.sets | Where-Object { $_ })) {
            $r = IniSet $txt ([string]$kv.section) ([string]$kv.key) ([string]$kv.value)
            [void]$u.Add(@{ t = 'ini'; path = $x; section = [string]$kv.section; key = [string]$kv.key; had = $r.had; old = $r.old })
            $txt = $r.text
          }
          if (-not $WhatIf) { WriteText $x $txt $f.enc }
        }
        'xml' {
          if ($a.notRunning -and @(Get-Process -Name $a.notRunning -ErrorAction SilentlyContinue).Count) { throw "$($a.notRunning -replace '\*','') läuft noch – bitte zuerst schließen." }
          $x = [Environment]::ExpandEnvironmentVariables([string]$a.path)
          if (-not (Test-Path -LiteralPath $x -PathType Leaf)) { throw 'SKIP:Einstellungsdatei nicht gefunden – starte das Spiel einmal und schließe es wieder' }
          $doc = LoadXml $x
          $par = $doc.SelectSingleNode('//' + [string]$a.parent)
          if (-not $par) { throw 'SKIP:Unbekanntes Dateiformat' }
          $chg = 0
          foreach ($pp in @($a.sets.PSObject.Properties)) {
            $node = $par.SelectSingleNode([string]$pp.Name)
            if (-not $node -or -not $node.HasAttribute('value')) { continue }
            [void]$u.Add(@{ t = 'xml'; path = $x; parent = [string]$a.parent; name = [string]$pp.Name; old = $node.GetAttribute('value') })
            if (-not $WhatIf) { $node.SetAttribute('value', [string]$pp.Value) }
            $chg++
          }
          if (-not $WhatIf -and $chg) { SaveXml $doc $x }
        }
        'layers' {
          $ex = ExeTargets $a.exes
          if ($ex.Count -eq 0) { throw 'SKIP:Spiel nicht am Standard-Ort gefunden' }
          $p = 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers'
          foreach ($f in $ex) {
            $e = RegUndo $p $f; [void]$u.Add($e)
            if (-not $WhatIf) {
              $cur = ''; if ($e.had) { $cur = [string]$e.value }
              $tok = @($cur -split '\s+' | Where-Object { $_ -and $_ -ne '~' })
              foreach ($fl in @($a.flags | Where-Object { $_ })) { if ($tok -notcontains [string]$fl) { $tok += [string]$fl } }
              RegSet $p $f ('~ ' + ($tok -join ' ')) 'String'
            }
          }
        }
        'mmagent' {
          if (-not (Get-Command Get-MMAgent -ErrorAction SilentlyContinue)) { throw 'SKIP:Speicherverwaltung ist auf diesem PC nicht verfügbar' }
          $was = [bool](Get-MMAgent).MemoryCompression
          if ($was -eq [bool]$a.enable) { throw 'SKIP:Ist bereits so eingestellt' }
          if (-not $WhatIf) { if ($a.enable) { Enable-MMAgent -MemoryCompression } else { Disable-MMAgent -MemoryCompression } }
          [void]$u.Add(@{ t = 'mmagent'; was = $was })
        }
        'hiber' {
          $hen = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name HibernateEnabled -ErrorAction SilentlyContinue).HibernateEnabled
          if ($hen -eq 0) { throw 'SKIP:Der Ruhezustand ist bereits aus' }
          $hf = Get-Item -LiteralPath (Join-Path $env:SystemDrive 'hiberfil.sys') -Force -ErrorAction SilentlyContinue
          if (-not $WhatIf) {
            powercfg /hibernate off | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Ruhezustand konnte nicht abgeschaltet werden.' }
            if ($hf) { $script:Freed += [int64]$hf.Length }
          }
          [void]$u.Add(@{ t = 'hiber' })
        }
      }
      } catch {
        # Schützt Windows nur diesen Teil, läuft der Rest weiter (statt alles zurückzurollen)
        $pm = ProtMsg $_
        if (-not $pm -or $WhatIf) { throw }
        [void]$script:ProtParts.Add($pm)
      }
    }
    if (-not $WhatIf -and $u.Count -eq 0 -and $script:ProtParts.Count) { $sm = 'SKIP:' + $script:ProtParts[0]; if ($t.protHint) { $sm += '. ' + $t.protHint }; throw $sm }
    # Nichts geändert (Dienst/Adapter/Einstellung gibt es hier nicht) -> übersprungen statt falsch als aktiv gemerkt
    if (-not $WhatIf -and $t.reversible -ne $false -and $u.Count -eq 0) { throw 'SKIP:Auf diesem PC gibt es dafür nichts zu ändern' }
  } catch {
    if (-not $WhatIf) { for ($i = $u.Count - 1; $i -ge 0; $i--) { try { Undo $u[$i] } catch {} } }
    throw
  }
  , @($u)
}

# Energie-Tweaks nach einem Planwechsel auf den aktiven Plan uebertragen
function ReapplyPwr($st) {
  $act = ActiveScheme
  foreach ($k in @($st.Keys | Where-Object { $_ -notlike '_*' })) {
    $undo = @($st[$k].undo | Where-Object { $_ })
    $pw = @($undo | Where-Object { $_.t -eq 'pwr' })
    if ($pw.Count -eq 0 -or @($pw | Where-Object { $_.scheme -ne $act }).Count -eq 0) { continue }
    if (-not (HasT $k)) { continue }
    try {
      for ($i = $undo.Count - 1; $i -ge 0; $i--) { try { Undo $undo[$i] } catch {} }
      $st.Remove($k)
      $nu = DoApply (GetT $k)
      $st[$k] = @{ applied = (Get-Date).ToString('s'); undo = $nu }
      Say "  $k auf den neuen Energieplan übertragen"
    } catch { Say "  $k konnte nicht übertragen werden: $($_.Exception.Message -replace '^SKIP:','')" 'warn' }
  }
}

function Rev($ids, $st) {
  $revPlan = $false
  $script:StepN = [math]::Max(1, @($ids | Where-Object { $st.ContainsKey($_) }).Count); $script:StepI = 0
  foreach ($i in $ids) {
    if (-not $st.ContainsKey($i)) { continue }
    $nm = $i; if (HasT $i) { $nm = (GetT $i).name }
    Step "Wird zurückgesetzt: $nm"
    $e = @($st[$i].undo | Where-Object { $_ })
    if (@($e | Where-Object { $_.t -eq 'plan' }).Count) { $revPlan = $true }
    if (-not $WhatIf) {
      for ($k = $e.Count - 1; $k -ge 0; $k--) { try { Undo $e[$k] } catch { Say "  Teilfehler: $($_.Exception.Message)" 'warn' } }
      $st.Remove($i)
    }
    Say "Zurückgesetzt: $nm" 'ok'
    $script:StepI++
  }
  foreach ($bk in @($st.Keys | Where-Object { $_ -notlike '_*' })) {
    if (-not $st[$bk].bundle) { continue }
    $mem = @($st[$bk].members | Where-Object { $_ })
    if ($mem.Count -eq 0 -or @($mem | Where-Object { -not $st.ContainsKey($_) }).Count -gt 0) {
      $bn = $bk; if (HasT $bk) { $bn = (GetT $bk).name }
      if (-not $WhatIf) { $st.Remove($bk) }
      Say "Zurückgesetzt: $bn" 'ok'
    }
  }
  if ($revPlan -and -not $WhatIf) { Step 'Energieplan wird wiederhergestellt …' -Prep; ReapplyPwr $st }
  $script:StepI = $script:StepN; Step 'Fertig'
  if (-not $WhatIf) { SaveState $st }
}

# ---------------------------------------------------------------- Autostart
function RunKey($sc) {
  switch ($sc) {
    'HKCU'   { 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' }
    'HKLM'   { 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' }
    'HKLM32' { 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run' }
  }
}
function StartupFolder($sc) {
  switch ($sc) {
    'FOLDERU' { [Environment]::GetFolderPath('Startup') }
    'FOLDERM' { [Environment]::GetFolderPath('CommonStartup') }
  }
}
function ApprovedKey($sc) {
  switch ($sc) {
    'FOLDERU' { 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder' }
    'FOLDERM' { 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder' }
    'HKCU'   { 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' }
    'HKLM'   { 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' }
    'HKLM32' { 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32' }
  }
}

# ---------------------------------------------------------------- Ping (parallel, für Ping-Test und Fortnite-Server)
function PingSet($hostList, $rounds) {
  $tms = @{}; $lostN = @{}
  foreach ($hn in $hostList) { $tms[$hn] = New-Object System.Collections.ArrayList; $lostN[$hn] = 0 }
  for ($k = 0; $k -lt $rounds; $k++) {
    $jobs = @()
    foreach ($hn in $hostList) { $pg = New-Object System.Net.NetworkInformation.Ping; $jobs += @{ h = $hn; t = $pg.SendPingAsync($hn, 1500) } }
    foreach ($jb in $jobs) {
      try { [void]$jb.t.Wait(2500) } catch {}
      $rp = $null
      if ([string]$jb.t.Status -eq 'RanToCompletion') { $rp = $jb.t.Result }
      if ($rp -and [string]$rp.Status -eq 'Success') { [void]$tms[$jb.h].Add([int]$rp.RoundtripTime) } else { $lostN[$jb.h]++ }
    }
    Start-Sleep -Milliseconds 150
  }
  $outp = @{}
  foreach ($hn in $hostList) {
    $tm = $tms[$hn]; $avg = 0; $min = 0; $max = 0; $jit = 0
    if ($tm.Count) {
      $avg = [math]::Round((($tm | Measure-Object -Average).Average), 1)
      $min = ($tm | Measure-Object -Minimum).Minimum; $max = ($tm | Measure-Object -Maximum).Maximum
      if ($tm.Count -gt 1) { $sum = 0; for ($q = 1; $q -lt $tm.Count; $q++) { $sum += [math]::Abs($tm[$q] - $tm[$q - 1]) }; $jit = [math]::Round($sum / ($tm.Count - 1), 1) }
    }
    $outp[$hn] = @{ avg = $avg; min = $min; max = $max; jitter = $jit; loss = [math]::Round($lostN[$hn] * 100 / $rounds) }
  }
  $outp
}

# ---------------------------------------------------------------- Autostart: Herausgeber und geplante Aufgaben
function StartupPub($cm) {
  $fp = $null
  if ([string]$cm -match '^\s*"([^"]+?\.exe)"') { $fp = $Matches[1] } elseif ([string]$cm -match '^\s*([^\s"]+?\.exe)\b') { $fp = $Matches[1] }
  if (-not $fp) { return '' }
  $fp = [Environment]::ExpandEnvironmentVariables($fp)
  if (-not (Test-Path -LiteralPath $fp -PathType Leaf)) { return '' }
  try {
    $sg = Get-AuthenticodeSignature -LiteralPath $fp -ErrorAction Stop
    if ([string]$sg.Status -eq 'Valid' -and $sg.SignerCertificate) { return [regex]::Match([string]$sg.SignerCertificate.Subject, 'CN="?([^",]+)').Groups[1].Value }
  } catch {}
  'nicht signiert'
}
function StartupTasks {
  $tl = @()
  try {
    foreach ($tk in @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -notlike '\Microsoft\*' })) {
      $lg = @($tk.Triggers | Where-Object { $_ -and ([string]$_.CimClass.CimClassName) -match 'Logon|Boot' })
      if (-not $lg.Count) { continue }
      $ac = @($tk.Actions | Where-Object { $_.Execute } | Select-Object -First 1)
      $cm = ''; if ($ac.Count) { $cm = ([string]$ac[0].Execute + ' ' + [string]$ac[0].Arguments).Trim() }
      $tl += @{ name = ([string]$tk.TaskPath + [string]$tk.TaskName); label = [string]$tk.TaskName; scope = 'TASK'; cmd = $cm; enabled = ([string]$tk.State -ne 'Disabled') }
    }
  } catch {}
  , @($tl)
}
function StartupTaskSet($full, $on) {
  $ix = ([string]$full).LastIndexOf('\')
  if ($ix -lt 0) { throw "Aufgabe nicht gefunden: $full" }
  $tp = $full.Substring(0, $ix + 1); $tn = $full.Substring($ix + 1)
  if ($tp -like '\Microsoft\*') { throw 'Windows-Aufgaben bleiben unverändert.' }
  $tk = Get-ScheduledTask -TaskPath $tp -TaskName $tn -ErrorAction Stop
  if ($on) { Enable-ScheduledTask -InputObject $tk -ErrorAction Stop | Out-Null } else { Disable-ScheduledTask -InputObject $tk -ErrorAction Stop | Out-Null }
}
function IntOr($v, $d) { $r = 0; if ($null -ne $v -and [int]::TryParse([string]$v, [ref]$r)) { return $r }; $d }

function GetStartupItems {
  $res = @()
  foreach ($sc in 'HKCU', 'HKLM', 'HKLM32') {
    $rk = RunKey $sc
    if (-not (Test-Path -LiteralPath $rk)) { continue }
    $k = Get-Item -LiteralPath $rk
    $ak = ApprovedKey $sc
    $ap = $null; if (Test-Path -LiteralPath $ak) { $ap = Get-Item -LiteralPath $ak }
    foreach ($n in @($k.GetValueNames())) {
      if (-not $n) { continue }
      $en = $true
      if ($ap -and (@($ap.GetValueNames()) -contains $n)) {
        $b = $ap.GetValue($n)
        if ($b -is [byte[]] -and $b.Length -gt 0) { $en = (($b[0] -band 1) -eq 0) }
      }
      $res += @{ name = $n; scope = $sc; cmd = [string]$k.GetValue($n); enabled = $en }
    }
  }
  foreach ($sc in 'FOLDERU', 'FOLDERM') {
    # Autostart-Ordner (Verknüpfungen), wie im Task-Manager
    $fd = StartupFolder $sc
    if (-not $fd -or -not (Test-Path -LiteralPath $fd)) { continue }
    $ak = ApprovedKey $sc
    $ap = $null; if (Test-Path -LiteralPath $ak) { $ap = Get-Item -LiteralPath $ak }
    $wsh = $null; try { $wsh = New-Object -ComObject WScript.Shell } catch {}
    foreach ($sf in @(Get-ChildItem -LiteralPath $fd -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' })) {
      $en = $true
      if ($ap -and (@($ap.GetValueNames()) -contains $sf.Name)) {
        $b = $ap.GetValue($sf.Name)
        if ($b -is [byte[]] -and $b.Length -gt 0) { $en = (($b[0] -band 1) -eq 0) }
      }
      $cm = $sf.FullName
      if ($wsh -and $sf.Extension -eq '.lnk') { try { $lk = $wsh.CreateShortcut($sf.FullName); if ($lk.TargetPath) { $cm = ([string]$lk.TargetPath + ' ' + [string]$lk.Arguments).Trim() } } catch {} }
      $res += @{ name = $sf.Name; label = $sf.BaseName; scope = $sc; cmd = $cm; enabled = $en }
    }
  }
  $res += (StartupTasks)
  foreach ($it in $res) { $it.pub = StartupPub $it.cmd }
  , @($res)
}

# ---------------------------------------------------------------- PC-Check
function HtmlE($v) { [System.Net.WebUtility]::HtmlEncode([string]$v) }
function AvgOf($arr) { $x = @($arr); if ($x.Count -eq 0) { return 0 }; [math]::Round(($x | Measure-Object -Average).Average, 1) }
function Hit($hid, $hcat, $sev, $title, $detail, $fix, $ref) {
  foreach ($it in $scanItems) { if ($it.id -eq [string]$hid) { return } }
  [void]$scanItems.Add(@{ id = [string]$hid; cat = $hcat; sev = $sev; title = [string]$title; detail = [string]$detail; fix = [string]$fix; ref = [string]$ref })
}

# ---------------------------------------------------------------- Befehle
$OK = $true
try {
  switch ($Command) {

    'List' {
      $st = LoadState
      $Data = @{ version = $Version; tweaks = $Tweaks; gamemode = $Cat.gamemode; applied = @($st.Keys | Where-Object { $_ -notlike '_*' }) }
    }

    'Test' {
      $bad = 0; $ids = @{}
      foreach ($t in $Tweaks) {
        if ($ids.ContainsKey($t.id)) { Say "Doppelte ID: $($t.id)" 'err'; $bad++ }
        $ids[$t.id] = $true
        if (-not $t.actions -and -not $t.includes) { Say "Tweak ohne Aktion: $($t.id)" 'err'; $bad++ }
        try { Guard $t } catch { Say $_.Exception.Message 'err'; $bad++ }
      }
      foreach ($t in $Tweaks) { foreach ($i in @($t.includes)) { if ($i -and -not $ids.ContainsKey($i)) { Say "Paket $($t.id): unbekannte ID $i" 'err'; $bad++ } } }
      foreach ($s in @($Cat.gamemode.services)) { if ($ProtNames -contains $s.name) { Say "Gaming-Modus darf $($s.name) nicht pausieren" 'err'; $bad++ } }
      foreach ($g in @($Cat.gamemode.groups)) { foreach ($n in @($g.procs)) { if ($Never -contains $n) { Say "Gruppe $($g.id): $n ist geschützt" 'err'; $bad++ } } }
      foreach ($n in $ProtNames) {
        $s = Get-CimInstance Win32_Service -Filter "Name='$n'" -ErrorAction SilentlyContinue
        $txt = 'nicht vorhanden'; if ($s) { $txt = "$($s.StartMode) / $($s.State)" }
        Say "  $n ($($Protected[$n])): $txt"
      }
      # Schreibtest: genau der Weg, den Tweaks mit neuen Schlüsseln gehen (anlegen, schreiben, sauber entfernen)
      $tp = 'HKCU:\Software\KaritoTweaksSelbsttest\Neu\Schluessel'
      try {
        $tu = RegUndo $tp 'Probe'
        RegSet $tp 'Probe' 1 'DWord'
        $okw = ((Get-ItemProperty -LiteralPath $tp -Name 'Probe' -ErrorAction Stop).Probe -eq 1)
        Undo $tu
        $gone = -not (Test-Path -LiteralPath 'HKCU:\Software\KaritoTweaksSelbsttest')
        if (-not $gone) { Remove-Item -LiteralPath 'HKCU:\Software\KaritoTweaksSelbsttest' -Recurse -Force -ErrorAction SilentlyContinue }
        if ($okw -and $gone) { Say 'Registry-Schreibtest: neuen Schlüssel anlegen, schreiben und entfernen OK' 'ok' }
        else { Say 'Registry-Schreibtest: unvollständig' 'err'; $bad++ }
      } catch { Say "Registry-Schreibtest fehlgeschlagen: $($_.Exception.Message)" 'err'; $bad++ }
      # Windows-Werkzeuge und versteckte Energieoptionen
      foreach ($tool in 'reg.exe', 'sc.exe', 'powercfg.exe') { if (-not (Test-Path -LiteralPath (Join-Path $env:SystemRoot "System32\$tool"))) { Say "$tool fehlt in System32" 'err'; $bad++ } }
      try { $pv = PwrGet (ActiveScheme) '0012ee47-9041-4b5d-9b77-535fba8b1442' '0b2d69d7-a2a1-449c-9680-f91c70521c60'; Say "Energieoptionen lesbar, auch versteckte (SSD-Verbindung: Stufe $pv)" 'ok' } catch { Say ('Energieoptionen: ' + ([string]$_.Exception.Message -replace '^SKIP:', '')) 'err'; $bad++ }
      foreach ($hf in 'KaritoTimer.ps1', 'KaritoInput.ps1') { if (Test-Path -LiteralPath (Join-Path $PSScriptRoot $hf)) { Say "$hf vorhanden" 'ok' } else { Say "$hf fehlt – vermutlich vom Virenschutz entfernt. Timer bzw. Live-Eingabe gehen dann nicht." 'warn' } }
      # Scanner (Clean-Check) liegt in eigenen Dateien – fehlen sie, laufen alle Tweaks trotzdem
      $scnf = Join-Path $PSScriptRoot 'KaritoScanner.ps1'
      if (-not (Test-Path -LiteralPath $scnf) -or -not (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'KaritoScanner.cs'))) {
        Say 'Scanner-Dateien fehlen (KaritoScanner.ps1/.cs) – vermutlich vom Virenschutz entfernt. Alle Tweaks funktionieren trotzdem.' 'err'; $bad++
      } else {
        try {
          . $scnf
          Say (Test-KaritoScanner) 'ok'
        } catch { Say "Scanner-Modul fehlgeschlagen: $($_.Exception.Message)" 'err'; $bad++ }
      }
      if ($bad) { throw "$bad Fehler gefunden (Engine $Version)." }
      Say "Katalog OK: $($Tweaks.Count) Tweaks · Schutzliste mit $($ProtNames.Count) Diensten aktiv · Engine $Version" 'ok'
    }

    'Status' {
      $st = LoadState
      $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
      $boot = Get-Date; if ($os) { $boot = $os.LastBootUpTime }
      if ($st.ContainsKey('_gm')) {
        $since = $null; try { $since = [datetime]$st['_gm'].since } catch {}
        if ($since -and $since -lt $boot -and (IsAdmin)) { $st.Remove('_gm'); SaveState $st }
      }
      $applied = @(); $restart = $false
      foreach ($k in @($st.Keys | Where-Object { $_ -notlike '_*' })) {
        $applied += @{ id = $k; applied = $st[$k].applied }
        if (HasT $k) {
          $t = GetT $k
          $at = $boot; try { $at = [datetime]$st[$k].applied } catch {}
          if ($t.restart -and $at -gt $boot) { $restart = $true }
        }
      }
      $prot = @()
      foreach ($n in $ProtNames) {
        $s = Get-CimInstance Win32_Service -Filter "Name='$n'" -ErrorAction SilentlyContinue
        $smode = 'n/a'; $sstate = 'n/a'
        if ($s) { $smode = [string]$s.StartMode; $sstate = [string]$s.State }
        $prot += @{ name = $n; label = $Protected[$n]; mode = $smode; state = $sstate }
      }
      $osName = ''; if ($os) { $osName = "$($os.Caption) ($($os.BuildNumber))" }
      $Data = @{
        version = $Version; admin = (IsAdmin); processes = @(Get-Process).Count; os = $osName
        applied = $applied; gamemode = $st.ContainsKey('_gm'); gm = $st['_gm']; needRestart = $restart; protected = $prot; pcsvc = @(PcSvcList)
      }
    }

    'Apply' {
      if ($Id.Count -eq 0) { throw 'Keine Tweaks ausgewählt.' }
      if (-not $WhatIf) { NeedAdmin }
      $list = ExpandIds $Id
      foreach ($i in $list) { Guard (GetT $i) }
      $st = LoadState
      $before = SnapModes
      $res = @(); $why = @{}
      $script:StepN = 0
      foreach ($i in $list) { $script:StepN += [math]::Max(1, @((GetT $i).actions | Where-Object { $null -ne $_ }).Count) }
      $script:StepI = 0; $stepNext = 0; $script:StepOn = $true
      if (-not $WhatIf -and @($list | Where-Object { (GetT $_).reversible -ne $false }).Count) {
        Step 'Wiederherstellungspunkt wird erstellt …' -Prep
        $cw = $null
        try {
          Checkpoint-Computer -Description 'Karito Tweaks' -RestorePointType MODIFY_SETTINGS -WarningAction SilentlyContinue -WarningVariable cw
          if ($cw) { Say 'Windows erlaubt nur einen Wiederherstellungspunkt pro 24 Stunden – die Rückgängig-Daten werden trotzdem gespeichert.' 'warn' }
          else { Say 'Wiederherstellungspunkt erstellt' 'ok' }
        } catch { Say 'Kein Wiederherstellungspunkt möglich (Computerschutz aus) – die Rückgängig-Daten werden trotzdem gespeichert.' 'warn' }
      }
      foreach ($i in $list) {
        $t = GetT $i
        $script:StepI = $stepNext; $script:StepAct = 0
        $stepNext += [math]::Max(1, @($t.actions | Where-Object { $null -ne $_ }).Count)
        Step "Wird angewendet: $($t.name)"
        if ($t.retired) { Say "Übersprungen: $($t.name) – in Version 2.0 entfernt ($($t.retired))" 'warn'; $res += @{ id = $i; status = 'skipped'; msg = 'retired' }; continue }
        if ($t.risk -ne 'low' -and -not $AcceptRisk) { Say "Übersprungen: $($t.name) (fortgeschritten – in der App „Alle anwenden“ wählen)" 'warn'; $why[$i] = 'risk'; $res += @{ id = $i; status = 'skipped'; msg = 'risk' }; continue }
        if ($st.ContainsKey($i) -and $t.reversible -ne $false) { Say "Bereits aktiv: $($t.name)"; $res += @{ id = $i; status = 'active' }; continue }
        try {
          $u = DoApply $t
          if (-not $WhatIf -and $t.reversible -ne $false) { $st[$i] = @{ applied = (Get-Date).ToString('s'); undo = $u }; SaveState $st }
          $msg = "OK: $($t.name)"
          if ($script:Freed -gt 0) { $msg += " ($([math]::Round($script:Freed / 1MB, 1)) MB)" }
          if ($WhatIf) { $msg = "Probelauf: $($t.name)" }
          $np = $script:ProtParts.Count
          if ($np) {
            $msg = "Teilweise: $($t.name) – $np $(if ($np -eq 1) { 'Einstellung schützt' } else { 'Einstellungen schützt' }) Windows, der Rest ist aktiv"
            if ($t.protHint) { $msg += '. ' + $t.protHint }
            Say $msg 'warn'
          } else { Say $msg 'ok' }
          $res += @{ id = $i; status = 'ok'; partial = $np; freed = $script:Freed; restart = [bool]$t.restart }
        } catch {
          $em = [string]$_.Exception.Message
          if ($em.StartsWith('SKIP:')) {
            $em = $em.Substring(5)
            Say "Übersprungen: $($t.name) – $em" 'warn'
            $res += @{ id = $i; status = 'skipped'; msg = $em }
          } else {
            $why[$i] = 'error'
            Say "Fehler: $($t.name) – $em (zurückgerollt)" 'err'
            $res += @{ id = $i; status = 'error'; msg = $em }
          }
        }
      }
      $script:StepOn = $false; $script:StepI = $script:StepN; Step 'Fertig'
      # Pakete (Hitreg, WASD, Profile) merken: aktiv, wenn nichts wegen Risiko oder Fehler fehlt
      foreach ($b in @($Id | Where-Object { (HasT $_) -and (GetT $_).includes })) {
        $bt = GetT $b
        $ms = ExpandIds @($b)
        $missing = @($ms | Where-Object { $why.ContainsKey($_) })
        $mem = @($ms | Where-Object { $st.ContainsKey($_) })
        if ($missing.Count -eq 0 -and $mem.Count -gt 0) {
          if (-not $WhatIf) { $st[$b] = @{ applied = (Get-Date).ToString('s'); undo = @(); bundle = $true; members = $mem }; SaveState $st }
          Say "Paket aktiv: $($bt.name)" 'ok'
        } elseif ($missing.Count -gt 0) {
          Say "„$($bt.name)“ ist nur teilweise aktiv – $($missing.Count) Tweak(s) fehlen noch." 'warn'
        }
      }
      if ($script:PlanChanged -and -not $WhatIf) { ReapplyPwr $st; SaveState $st }
      if ((SnapModes) -ne $before) { Say 'WARNUNG: Der Startmodus eines geschützten Dienstes hat sich verändert!' 'err' }
      else { Say "Schutzliste geprüft: alle $($ProtNames.Count) Dienste unverändert" 'ok' }
      $Data = @{ results = $res }
    }

    'Revert' {
      if ($Id.Count -eq 0) { throw 'Keine Tweaks ausgewählt.' }
      if (-not $WhatIf) { NeedAdmin }
      $st = LoadState
      $list = New-Object System.Collections.ArrayList
      # Tweaks, die ein anderes aktives Paket noch braucht, bleiben beim Zurücksetzen eines Pakets stehen
      $keep = @{}
      foreach ($ob in @($st.Keys | Where-Object { $_ -notlike '_*' -and $Id -notcontains $_ })) {
        if ($st[$ob].bundle) { foreach ($mb in @($st[$ob].members | Where-Object { $_ })) { $keep[$mb] = $ob } }
      }
      foreach ($i in $Id) {
        if (HasT $i) {
          $isBundle = [bool](GetT $i).includes
          foreach ($j in (ExpandIds @($i))) {
            if ($isBundle -and $keep.ContainsKey($j) -and $st.ContainsKey($j)) {
              $kn = $keep[$j]; if (HasT $kn) { $kn = (GetT $kn).name }
              Say "  $((GetT $j).name) bleibt aktiv – gehört auch zu „$kn“"
              continue
            }
            if (-not $list.Contains($j)) { [void]$list.Add($j) }
          }
        }
        elseif ($st.ContainsKey($i) -and -not $list.Contains($i)) { [void]$list.Add($i) }
      }
      $ordered = @($list | Sort-Object { Idx $_ } -Descending)
      if (@($ordered | Where-Object { $st.ContainsKey($_) }).Count -eq 0) { Say 'Nichts zurückzusetzen – diese Tweaks sind nicht aktiv.' }
      Rev $ordered $st
      foreach ($i in $Id) {
        if ($st.ContainsKey($i) -and $st[$i].bundle) {
          $bn = $i; if (HasT $i) { $bn = (GetT $i).name }
          if (-not $WhatIf) { $st.Remove($i); SaveState $st }
          Say "Zurückgesetzt: $bn" 'ok'
        }
      }
      $Data = @{}
    }

    'RevertAll' {
      if (-not $WhatIf) { NeedAdmin }
      $st = LoadState
      $keys = @($st.Keys | Where-Object { $_ -notlike '_*' } | Sort-Object { Idx $_ } -Descending)
      if ($keys.Count -eq 0) { Say 'Es sind keine Tweaks aktiv.' }
      Rev $keys $st
      $Data = @{}
    }

    'GameModeOn' {
      NeedAdmin
      $st = LoadState
      $gm = $Cat.gamemode
      $before = @(Get-Process).Count
      $closed = @(); $paused = @()
      foreach ($g in @($gm.groups | Where-Object { $Close -contains $_.id })) {
        foreach ($n in @($g.procs)) {
          if ($Never -contains $n) { Say "  $n ist geschützt und bleibt offen" 'warn'; continue }
          $ps = @(Get-Process -Name $n -ErrorAction SilentlyContinue)
          if ($ps.Count) { $ps | Stop-Process -Force -ErrorAction SilentlyContinue; $closed += $n }
        }
      }
      if ($PauseServices) {
        $prev = @(); if ($st.ContainsKey('_gm') -and $st['_gm'].paused) { $prev = @($st['_gm'].paused) }
        foreach ($s in @($gm.services)) {
          $n = [string]$s.name
          if ($ProtNames -contains $n) { continue }
          $sv = Get-Service -Name $n -ErrorAction SilentlyContinue
          if (-not $sv -or $sv.Status -ne 'Running') { continue }
          $deps = @($sv.DependentServices | Where-Object { $_.Status -eq 'Running' } | ForEach-Object { $_.Name })
          if (@($deps | Where-Object { $ProtNames -contains $_ }).Count) { Say "  $n übersprungen – ein geschützter Dienst hängt davon ab" 'warn'; continue }
          try { Stop-Service -Name $n -Force -ErrorAction Stop; $paused += $deps; $paused += $n }
          catch { Say "  $n konnte nicht pausiert werden" 'warn' }
        }
        $paused = @(@($prev) + @($paused) | Where-Object { $_ } | Select-Object -Unique)
      }
      Start-Sleep -Milliseconds 800
      $after = @(Get-Process).Count
      $st['_gm'] = @{ on = $true; since = (Get-Date).ToString('s'); closed = $closed; paused = $paused; before = $before; after = $after }
      SaveState $st
      Say "Gaming-Modus an: $before → $after Prozesse ($($closed.Count) Apps geschlossen, $($paused.Count) Dienste pausiert)" 'ok'
      $Data = @{ before = $before; after = $after; closed = $closed; paused = $paused }
    }

    'GameModeOff' {
      NeedAdmin
      $st = LoadState
      $started = @()
      if ($st.ContainsKey('_gm')) {
        $p = @($st['_gm'].paused | Where-Object { $_ })
        [array]::Reverse($p)
        foreach ($n in $p) { try { Start-Service -Name $n -ErrorAction Stop; $started += $n } catch { Say "  $n konnte nicht gestartet werden" 'warn' } }
        $st.Remove('_gm'); SaveState $st
      }
      Say 'Gaming-Modus aus – pausierte Dienste laufen wieder. Geschlossene Apps startest du bei Bedarf selbst.' 'ok'
      $Data = @{ started = $started; processes = @(Get-Process).Count }
    }

    'StartupList' {
      $si = GetStartupItems
      $Data = @{ items = $si }
    }

    'StartupSet' {
      NeedAdmin
      if (-not $Name) { throw 'Name fehlt.' }
      if ($Name -like 'svc:*') {
        # Dienste-Check – läuft über StartupSet, damit er per Update auch mit der installierten main.js funktioniert
        $res = @()
        foreach ($sn in @($Name.Substring(4) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
          $key = @($PcSvc.Keys | Where-Object { $_ -ieq $sn })
          if (-not $key.Count) { Say "Unbekannter Dienst: $sn" 'warn'; continue }
          $res += PcSvcSet $key[0] ([bool]$Enable)
        }
        $Data = @{ services = @(PcSvcList); changed = $res }
        break
      }
      if ($Scope -eq 'TASK') { StartupTaskSet $Name ([bool]$Enable); $tw = 'deaktiviert'; if ($Enable) { $tw = 'aktiviert' }; Say "$Name $tw" 'ok'; $Data = @{ name = $Name; enabled = [bool]$Enable }; break }
      if ($Scope -like 'FOLDER*') {
        $fd = StartupFolder $Scope
        if (-not $fd -or -not (Test-Path -LiteralPath (Join-Path $fd $Name) -PathType Leaf)) { throw "Autostart-Eintrag nicht gefunden: $Name" }
      } else {
        $rk = RunKey $Scope
        if (-not (Test-Path -LiteralPath $rk) -or -not (@((Get-Item -LiteralPath $rk).GetValueNames()) -contains $Name)) { throw "Autostart-Eintrag nicht gefunden: $Name" }
      }
      if ($Name -match 'SecurityHealth') { throw 'Windows-Sicherheit bleibt im Autostart.' }
      $ak = ApprovedKey $Scope
      if (-not (Test-Path -LiteralPath $ak)) { New-Item -Path $ak -Force | Out-Null }
      $b = New-Object byte[] 12
      if ($Enable) { $b[0] = 2 } else {
        $b[0] = 3
        $ft = [BitConverter]::GetBytes((Get-Date).ToFileTimeUtc())
        [Array]::Copy($ft, 0, $b, 4, 8)
      }
      New-ItemProperty -LiteralPath $ak -Name $Name -Value $b -PropertyType Binary -Force | Out-Null
      $w = 'deaktiviert'; if ($Enable) { $w = 'aktiviert' }
      Say "$Name $w" 'ok'
      $Data = @{ name = $Name; enabled = [bool]$Enable }
    }

    'InputGet' {
      $kb = Get-ItemProperty -LiteralPath 'HKCU:\Control Panel\Keyboard' -ErrorAction SilentlyContinue
      $ms = Get-ItemProperty -LiteralPath 'HKCU:\Control Panel\Mouse' -ErrorAction SilentlyContinue
      $Data = @{ delay = (IntOr $kb.KeyboardDelay 1); speed = (IntOr $kb.KeyboardSpeed 31); mouse = (IntOr $ms.MouseSensitivity 10); live = $false }
    }

    'InputSet' {
      # Rückfall ohne Live-Helfer: Werte speichern, Windows übernimmt sie bei der nächsten Anmeldung
      if ($KbDelay -ge 0) { if ($KbDelay -gt 3) { throw 'Tastatur-Verzögerung: 0 bis 3.' }; RegSet 'HKCU:\Control Panel\Keyboard' 'KeyboardDelay' ([string]$KbDelay) 'String' }
      if ($KbSpeed -ge 0) { if ($KbSpeed -gt 31) { throw 'Wiederholrate: 0 bis 31.' }; RegSet 'HKCU:\Control Panel\Keyboard' 'KeyboardSpeed' ([string]$KbSpeed) 'String' }
      if ($MouseSpeed -ge 0) { if ($MouseSpeed -lt 1 -or $MouseSpeed -gt 20) { throw 'Mausgeschwindigkeit: 1 bis 20.' }; RegSet 'HKCU:\Control Panel\Mouse' 'MouseSensitivity' ([string]$MouseSpeed) 'String' }
      Say 'Gespeichert – wirkt nach der nächsten Anmeldung.' 'ok'
      $Data = @{ live = $false }
    }

    'Hardware' {
      # Hardware dieses PCs – nur lesend
      $hw = [ordered]@{}
      try { $cp = @(Get-CimInstance Win32_Processor)[0]; $hw.cpu = @{ name = ([string]$cp.Name).Trim(); cores = [int]$cp.NumberOfCores; threads = [int]$cp.NumberOfLogicalProcessors; mhz = [int]$cp.MaxClockSpeed; socket = [string]$cp.SocketDesignation } } catch {}
      try {
        # Win32_VideoController.AdapterRAM ist bei mehr als 4 GB falsch – der Treiber-Eintrag kennt die echte Größe
        $vram = @{}
        foreach ($sk in @(Get-ChildItem -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^\d{4}$' })) {
          try {
            $pv = Get-ItemProperty -LiteralPath $sk.PSPath -ErrorAction Stop
            $qv = $pv.'HardwareInformation.qwMemorySize'
            if ($qv -is [byte[]] -and $qv.Length -ge 8) { $qv = [BitConverter]::ToInt64($qv, 0) }
            if ($pv.DriverDesc -and $null -ne $qv) { $vram[[string]$pv.DriverDesc] = [int64]$qv }
          } catch {}
        }
        $gl = @()
        foreach ($vc in @(Get-CimInstance Win32_VideoController)) {
          $vb = [int64]$vc.AdapterRAM; if ($vram.ContainsKey([string]$vc.Name)) { $vb = $vram[[string]$vc.Name] }
          $gl += @{ name = [string]$vc.Name; driver = [string]$vc.DriverVersion; vramMB = [int]($vb / 1MB); width = [int]$vc.CurrentHorizontalResolution; height = [int]$vc.CurrentVerticalResolution; hz = [int]$vc.CurrentRefreshRate }
        }
        $hw.gpu = $gl
      } catch {}
      try {
        $mods = @(Get-CimInstance Win32_PhysicalMemory)
        $sum = [int64]0; foreach ($md in $mods) { $sum += [int64]$md.Capacity }
        $hw.ram = @{ totalGB = [math]::Round($sum / 1GB, 1); modules = @($mods | ForEach-Object { @{ sizeGB = [int]([int64]$_.Capacity / 1GB); speed = [int]$_.Speed; configured = [int]$_.ConfiguredClockSpeed; maker = ([string]$_.Manufacturer).Trim(); part = ([string]$_.PartNumber).Trim(); slot = [string]$_.DeviceLocator } }) }
      } catch {}
      try { $bb = Get-CimInstance Win32_BaseBoard; $hw.board = @{ maker = ([string]$bb.Manufacturer).Trim(); model = ([string]$bb.Product).Trim() } } catch {}
      try { $bi = Get-CimInstance Win32_BIOS; $bd = ''; if ($bi.ReleaseDate) { $bd = ([datetime]$bi.ReleaseDate).ToString('dd.MM.yyyy') }; $hw.bios = @{ version = ([string]$bi.SMBIOSBIOSVersion).Trim(); date = $bd } } catch {}
      try { $hw.disks = @(Get-PhysicalDisk -ErrorAction Stop | Sort-Object DeviceId | ForEach-Object { @{ name = ([string]$_.FriendlyName).Trim(); type = [string]$_.MediaType; bus = [string]$_.BusType; sizeGB = [int]([int64]$_.Size / 1GB); health = [string]$_.HealthStatus } }) } catch {}
      try {
        $osx = Get-CimInstance Win32_OperatingSystem
        $dv = [string](Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name DisplayVersion -ErrorAction SilentlyContinue).DisplayVersion
        $hw.os = @{ name = [string]$osx.Caption; version = $dv; build = [string]$osx.BuildNumber; arch = [string]$osx.OSArchitecture }
      } catch {}
      try { $hw.net = @(Get-NetAdapter -Physical -ErrorAction Stop | Sort-Object Status, Name | ForEach-Object { @{ name = [string]$_.Name; desc = [string]$_.InterfaceDescription; speed = [string]$_.LinkSpeed; status = [string]$_.Status } }) } catch {}
      try {
        $hw.monitors = @(Get-CimInstance -Namespace 'root\wmi' -ClassName WmiMonitorID -ErrorAction Stop | ForEach-Object {
          $mn = -join (@($_.UserFriendlyName) | Where-Object { $_ -ne 0 } | ForEach-Object { [char]$_ })
          $mk = -join (@($_.ManufacturerName) | Where-Object { $_ -ne 0 } | ForEach-Object { [char]$_ })
          @{ name = $mn.Trim(); maker = $mk.Trim() }
        })
      } catch {}
      try { $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop; $hw.vbs = ([int]$dg.VirtualizationBasedSecurityStatus -eq 2) } catch {}
      try { $hw.hags = ((Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' -Name HwSchMode -ErrorAction Stop).HwSchMode -eq 2) } catch { $hw.hags = $false }
      try { $apo = powercfg /getactivescheme | Out-String; $hw.plan = [regex]::Match($apo, '\((.+)\)').Groups[1].Value } catch {}
      $Data = $hw
    }

    'Hwid' {
      $bad = '^(|0+|F+|none|default string|to be filled by o\.e\.m\.|system serial number|00000000-0000-0000-0000-000000000000|ffffffff-ffff-ffff-ffff-ffffffffffff|03000200-0400-0500-0006-000700080009)$'
      $parts = @()
      try { $parts += [string](Get-CimInstance Win32_ComputerSystemProduct).UUID } catch {}
      try { $parts += [string](Get-CimInstance Win32_BaseBoard).SerialNumber } catch {}
      try { $parts += [string](@(Get-CimInstance Win32_DiskDrive | Sort-Object Index)[0].SerialNumber) } catch {}
      try { $parts += [string](Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid } catch {}
      $parts = @($parts | ForEach-Object { $_.Trim() } | Where-Object { $_ -notmatch $bad })
      if ($parts.Count -eq 0) { throw 'Hardware-ID konnte nicht ermittelt werden.' }
      $raw = ($parts -join '|') + '|karito-v1'
      $sha = [System.Security.Cryptography.SHA256]::Create()
      $hash = ($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($raw)) | ForEach-Object { $_.ToString('x2') }) -join ''
      $Data = @{ hwid = $hash.Substring(0, 32).ToUpper() }
    }

    'NetTest' {
      if ($Mode -eq 'Fortnite') {
        # Epic-Ping-Adressen je Region und Subregion – der beste Wert ist die Subregion für die Fortnite-Einstellung
        $eps = @(
          @{ h = 'ping-eu.ds.on.epicgames.com'; l = 'Europa'; r = 'EU' }, @{ h = 'ping-de.ds.on.epicgames.com'; l = 'Deutschland'; r = 'EU' },
          @{ h = 'ping-gb.ds.on.epicgames.com'; l = 'Großbritannien'; r = 'EU' }, @{ h = 'ping-fr.ds.on.epicgames.com'; l = 'Frankreich'; r = 'EU' },
          @{ h = 'ping-nae.ds.on.epicgames.com'; l = 'NA-Ost'; r = 'NA' }, @{ h = 'ping-va.ds.on.epicgames.com'; l = 'Virginia'; r = 'NA' },
          @{ h = 'ping-oh.ds.on.epicgames.com'; l = 'Ohio'; r = 'NA' }, @{ h = 'ping-nac.ds.on.epicgames.com'; l = 'NA-Mitte'; r = 'NA' },
          @{ h = 'ping-ia.ds.on.epicgames.com'; l = 'Iowa'; r = 'NA' }, @{ h = 'ping-tx.ds.on.epicgames.com'; l = 'Texas'; r = 'NA' },
          @{ h = 'ping-mx.ds.on.epicgames.com'; l = 'Mexiko'; r = 'NA' }, @{ h = 'ping-naw.ds.on.epicgames.com'; l = 'NA-West'; r = 'NA' },
          @{ h = 'ping-ncal.ds.on.epicgames.com'; l = 'Nordkalifornien'; r = 'NA' }, @{ h = 'ping-or.ds.on.epicgames.com'; l = 'Oregon'; r = 'NA' },
          @{ h = 'ping-br.ds.on.epicgames.com'; l = 'Brasilien'; r = 'BR' }, @{ h = 'ping-sao.ds.on.epicgames.com'; l = 'São Paulo'; r = 'BR' },
          @{ h = 'ping-me.ds.on.epicgames.com'; l = 'Naher Osten'; r = 'ME' }, @{ h = 'ping-bah.ds.on.epicgames.com'; l = 'Bahrain'; r = 'ME' },
          @{ h = 'ping-il.ds.on.epicgames.com'; l = 'Israel'; r = 'ME' }, @{ h = 'ping-asia.ds.on.epicgames.com'; l = 'Asien'; r = 'ASIA' },
          @{ h = 'ping-tok.ds.on.epicgames.com'; l = 'Tokio'; r = 'ASIA' }, @{ h = 'ping-mum.ds.on.epicgames.com'; l = 'Mumbai'; r = 'ASIA' },
          @{ h = 'ping-oce.ds.on.epicgames.com'; l = 'Ozeanien'; r = 'OCE' }, @{ h = 'ping-syd.ds.on.epicgames.com'; l = 'Sydney'; r = 'OCE' }
        )
        $pr = PingSet @($eps | ForEach-Object { $_.h }) 6
        $res = @()
        foreach ($ep in $eps) { $sv = $pr[$ep.h]; $res += @{ host = $ep.h; label = $ep.l; region = $ep.r; avg = $sv.avg; min = $sv.min; max = $sv.max; jitter = $sv.jitter; loss = $sv.loss } }
        $reach = @($res | Where-Object { $_.loss -lt 100 } | Sort-Object { [double]$_.avg })
        $bestHost = $null
        if ($reach.Count) { $bestHost = $reach[0].host; Say ('Niedrigster Ping: ' + $reach[0].label + ' – Ø ' + $reach[0].avg + ' ms, Jitter ' + $reach[0].jitter + ' ms') 'ok' }
        else { Say 'Kein Fortnite-Server erreichbar – Internetverbindung oder Firewall prüfen.' 'warn' }
        $Data = @{ results = $res; best = $bestHost }
      } else {
        $hl = @('1.1.1.1', '8.8.8.8')
        $pr = PingSet $hl 10
        $res = @()
        foreach ($hn in $hl) { $sv = $pr[$hn]; $res += @{ host = $hn; avg = $sv.avg; min = $sv.min; max = $sv.max; jitter = $sv.jitter; loss = $sv.loss }; Say "${hn}: Ø $($sv.avg) ms · Jitter $($sv.jitter) ms · Verlust $($sv.loss) %" 'ok' }
        $Data = @{ results = $res }
      }
    }

    'Perf' {
      $cpuS = @(); $dpcS = @(); $irqS = @()
      for ($k = 0; $k -lt 6; $k++) {
        $pp = Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'" -ErrorAction SilentlyContinue
        if ($pp -and $k -gt 0) { $cpuS += [double]$pp.PercentProcessorTime; $dpcS += [double]$pp.PercentDPCTime; $irqS += [double]$pp.PercentInterruptTime }
        Start-Sleep -Milliseconds 700
      }
      $osp = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
      $ramPct = 0; if ($osp) { $ramPct = [math]::Round((1 - $osp.FreePhysicalMemory / $osp.TotalVisibleMemorySize) * 100) }
      $Data = @{ cpu = (AvgOf $cpuS); dpc = (AvgOf $dpcS); irq = (AvgOf $irqS); ram = $ramPct; processes = @(Get-Process).Count; time = (Get-Date).ToString('s') }
      Say "Leerlauf: CPU $($Data.cpu) % · DPC $($Data.dpc) % · Interrupts $($Data.irq) % · RAM $ramPct % · $($Data.processes) Prozesse" 'ok'
    }

    'Scan' {
      $scanItems = New-Object System.Collections.ArrayList
      $st = LoadState
      if ($Mode -eq 'Health') {
        try {
          $plist = @(Get-Process)
          $pc = $plist.Count
          $svh = @($plist | Where-Object { $_.Name -eq 'svchost' }).Count
          $top = (@($plist | Group-Object Name | Sort-Object Count -Descending | Select-Object -First 8 | ForEach-Object { "$($_.Name) ×$($_.Count)" })) -join ', '
          $sev = 'ok'; if ($pc -gt 200) { $sev = 'warn' } elseif ($pc -gt 150) { $sev = 'info' }
          $fix = ''; if ($svh -gt 45 -and -not $st.ContainsKey('svchost-group')) { $fix = 'svchost-group' }
          Hit 'procs' 'Prozesse' $sev "$pc Prozesse laufen ($svh davon svchost)" "Größte Gruppen: $top" $fix
        } catch {}
        try {
          $pso = powercfg /getactivescheme | Out-String
          if ($st.ContainsKey('power-ultimate') -or $pso -match 'Ultimat|chstleistung|High performance') { Hit 'plan' 'Energie' 'ok' 'Leistungs-Energieplan aktiv' '' '' }
          else { Hit 'plan' 'Energie' 'warn' 'Energiesparplan bremst den PC' 'Aktiv ist kein Leistungsplan.' 'power-ultimate' }
        } catch {}
        $gb = Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\GameBar' -ErrorAction SilentlyContinue
        if ($gb -and $gb.PSObject.Properties['AutoGameModeEnabled'] -and $gb.AutoGameModeEnabled -eq 0) { Hit 'gamemode' 'System' 'warn' 'Spielmodus ist aus' 'Windows priorisiert Spiele dann nicht.' 'gamemode-hags' }
        else { Hit 'gamemode' 'System' 'ok' 'Spielmodus an' '' '' }
        $gd = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' -ErrorAction SilentlyContinue
        if ($gd -and $gd.PSObject.Properties['HwSchMode'] -and $gd.HwSchMode -eq 1) { Hit 'hags' 'Grafik' 'warn' 'GPU-Scheduling (HAGS) ist aus' 'Mit aktueller Grafikkarte meist besser an.' 'gamemode-hags' }
        $dvr = Get-ItemProperty -LiteralPath 'HKCU:\System\GameConfigStore' -ErrorAction SilentlyContinue
        if (-not $dvr -or -not $dvr.PSObject.Properties['GameDVR_Enabled'] -or $dvr.GameDVR_Enabled -ne 0) { Hit 'dvr' 'System' 'warn' 'Hintergrundaufnahme (Game DVR) aktiv' 'Kostet GPU-Leistung.' 'gamedvr-off' }
        else { Hit 'dvr' 'System' 'ok' 'Game DVR aus' '' '' }
        $mo = Get-ItemProperty -LiteralPath 'HKCU:\Control Panel\Mouse' -ErrorAction SilentlyContinue
        if ($mo -and [string]$mo.MouseSpeed -ne '0') { Hit 'accel' 'Eingabe' 'warn' 'Maus-Beschleunigung an' 'Macht dein Aim ungleichmäßig.' 'mouse-accel-off' }
        else { Hit 'accel' 'Eingabe' 'ok' 'Maus-Beschleunigung aus' '' '' }
        $mmp = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' -ErrorAction SilentlyContinue
        if ($mmp -and $mmp.NetworkThrottlingIndex -ne -1) { Hit 'throttle' 'Netzwerk' 'info' 'Network-Throttling aktiv' 'Windows drosselt Netzwerkpakete bei Multimedia.' 'net-throttle-off' }
        try {
          $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
          if ($dg.VirtualizationBasedSecurityStatus -eq 2) { Hit 'vbs' 'System' 'info' 'Speicher-Integrität (VBS) läuft' 'Kann FPS kosten – Abschalten ist eine Sicherheits-Abwägung.' 'vbs-off' }
        } catch {}
        try {
          $all = GetStartupItems
          $su = @($all | Where-Object { $_.enabled })
          if ($su.Count -gt 8) { Hit 'startup' 'Autostart' 'warn' "$($su.Count) Programme im Autostart" 'Jedes kostet Prozesse und Startzeit.' 'view:startup' }
          else { Hit 'startup' 'Autostart' 'ok' "$($su.Count) Programme im Autostart" '' '' }
        } catch {}
        try {
          $cd = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
          $pct = [math]::Round($cd.FreeSpace / $cd.Size * 100)
          if ($pct -lt 15) { Hit 'disk' 'Speicher' 'warn' "Nur noch $pct % frei auf C:" 'Wenig Platz bremst Updates und Shader-Caches.' 'view:clean' }
          else { Hit 'disk' 'Speicher' 'ok' "$pct % frei auf C:" '' '' }
          $tsz = DirSize $env:TEMP
          if ($tsz -gt 1GB) { Hit 'temp' 'Speicher' 'info' "$([math]::Round($tsz / 1GB, 1)) GB Temp-Dateien" '' 'temp-clean' }
        } catch {}
        try {
          $cs = Get-CimInstance Win32_ComputerSystem
          $ram = [math]::Round($cs.TotalPhysicalMemory / 1GB)
          if ($ram -lt 16) { Hit 'ram' 'Hardware' 'info' "$ram GB Arbeitsspeicher" 'Für aktuelle Spiele sind 16 GB oder mehr empfohlen.' '' } else { Hit 'ram' 'Hardware' 'ok' "$ram GB Arbeitsspeicher" '' '' }
          $cpu = @(Get-CimInstance Win32_Processor)[0]
          $opts = [string](Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name SystemStartOptions -ErrorAction SilentlyContinue).SystemStartOptions
          if ($opts -match 'NUMPROC=\s*(\d+)') { Hit 'cores' 'Hardware' 'warn' "CPU-Kerne begrenzt auf $($Matches[1])" 'msconfig → Start → Erweiterte Optionen: Haken bei „Anzahl der Prozessoren“ entfernen und neu starten.' '' }
          else { Hit 'cores' 'Hardware' 'ok' "Alle $($cpu.NumberOfCores) Kerne / $($cpu.NumberOfLogicalProcessors) Threads aktiv" 'Windows nutzt automatisch alle Kerne – msconfig kann sie nur begrenzen.' '' }
          $thr = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name SvcHostSplitThresholdInKB -ErrorAction SilentlyContinue).SvcHostSplitThresholdInKB
          if ($null -ne $thr) {
            $tv = [int64]$thr; if ($tv -lt 0) { $tv += 4294967296 }
            if ($tv -lt [int64]($cs.TotalPhysicalMemory / 1KB)) { Hit 'svcsplit' 'Prozesse' 'info' 'Jeder Dienst läuft als eigener Prozess' 'Dienste bündeln spart oft 40 bis 80 Prozesse.' 'svchost-group' }
          }
        } catch {}
        try {
          foreach ($g in @(Get-CimInstance Win32_VideoController | Where-Object { $_.Name -notmatch 'Basic|Remote|Virtual|Parsec|Meta' })) {
            if ($g.DriverDate) {
              $age = ((Get-Date) - [datetime]$g.DriverDate).Days
              if ($age -gt 180) { Hit "gpu$($g.DeviceID)" 'Grafik' 'info' "Grafiktreiber ist $age Tage alt" "$($g.Name) – ein aktueller Treiber bringt oft mehr als jeder Tweak." '' }
              else { Hit "gpu$($g.DeviceID)" 'Grafik' 'ok' 'Grafiktreiber aktuell' "$($g.Name)" '' }
            }
          }
        } catch {}
        try {
          $ap2 = 'HKLM:\SOFTWARE\Microsoft\WindowsSelfHost\Applicability'
          if (Test-Path -LiteralPath $ap2) { $br = (Get-ItemProperty -LiteralPath $ap2 -ErrorAction SilentlyContinue).BranchName; if ($br) { Hit 'insider' 'System' 'info' "Windows-Insider-Build ($br)" 'Neue Builds verhalten sich manchmal anders als normale Windows-Versionen.' '' } }
          $wsv = Get-Service -Name WSearch -ErrorAction SilentlyContinue
          if ($wsv -and $wsv.Status -eq 'Running') { Hit 'search' 'Prozesse' 'info' 'Windows-Suchindex läuft im Hintergrund' 'Kostet Prozesse und Datenträger-Last.' 'svc-search-off' }
          $hb = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name HiberbootEnabled -ErrorAction SilentlyContinue).HiberbootEnabled
          if ($hb -eq 1) { Hit 'faststart' 'System' 'info' 'Schnellstart ist an' 'Treiber starten nicht frisch – Schnellstart aus hilft gegen Ruckler nach dem Hochfahren.' 'fast-startup-off' }
          $wd = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh' -Name AllowNewsAndInterests -ErrorAction SilentlyContinue).AllowNewsAndInterests
          if ($wd -ne 0) { Hit 'widgets' 'Prozesse' 'info' 'Widgets laufen im Hintergrund' '' 'widgets-off' }
          $usb = PwrGet (ActiveScheme) '2a737441-1930-4402-8d77-b2bebba308a3' '48e6b7a6-50f5-4782-a5d4-53bb8f07e226'
          if ($usb -ne 0) { Hit 'usb' 'Eingabe' 'info' 'USB-Energiesparen aktiv' 'Maus und Tastatur können kurz einschlafen.' 'usb-suspend-off' }
        } catch {}
      } else {
        # Der Clean-Check liegt in eigenen Dateien (KaritoScanner.ps1/.cs). Fehlen sie, laufen alle Tweaks trotzdem.
        $scnf = Join-Path $PSScriptRoot 'KaritoScanner.ps1'
        if (-not (Test-Path -LiteralPath $scnf) -or -not (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'KaritoScanner.cs'))) { throw 'Die Scanner-Dateien fehlen (engine\KaritoScanner.ps1 und .cs) – vermutlich hat der Virenschutz sie entfernt. Prüfe Windows-Sicherheit → Viren- & Bedrohungsschutz → Schutzverlauf. Alle Tweaks funktionieren weiter.' }
        . $scnf
        Invoke-KaritoIntegrity
      }
      $score = 100
      foreach ($it in $scanItems) { switch ($it.sev) { 'crit' { $score -= 15 } 'warn' { $score -= 8 } 'info' { $score -= 3 } } }
      if ($score -lt 0) { $score = 0 }
      $crit = @($scanItems | Where-Object { $_.sev -eq 'crit' }).Count
      $warn = @($scanItems | Where-Object { $_.sev -eq 'warn' }).Count
      $risk = $null; $cleanLvl = $null; $tline = @()
      if ($Mode -eq 'Integrity') {
        $verdict = 'CLEAN'; if ($crit) { $verdict = 'KRITISCH' } elseif ($warn) { $verdict = 'PRÜFEN' }
        $risk = 'NIEDRIG'
        if ($crit -ge 2 -or ($crit -ge 1 -and $script:cleanPts -ge 3)) { $risk = 'SCHWER' } elseif ($crit -ge 1) { $risk = 'HOCH' } elseif ($warn -ge 1) { $risk = 'MITTEL' }
        $cleanLvl = 'keine'; if ($script:cleanPts -ge 6) { $cleanLvl = 'hoch' } elseif ($script:cleanPts -ge 3) { $cleanLvl = 'mittel' } elseif ($script:cleanPts -ge 1) { $cleanLvl = 'leicht' }
        $tline = @($script:timeline | Sort-Object { $_.t } -Descending | Select-Object -First 80)
      } else { $verdict = 'AUSBAUFÄHIG'; if ($score -ge 85) { $verdict = 'TOP' } elseif ($score -ge 60) { $verdict = 'GUT' } }
      $cpts = 0; if ($Mode -eq 'Integrity') { $cpts = [int]$script:cleanPts }
      $report = $null; $reportTxt = $null
      if ($Save) {
        $rdir = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Karito-Berichte'
        New-Item -ItemType Directory -Force -Path $rdir | Out-Null
        $mt = 'Optimierung'; $mf = 'Optimierung'; if ($Mode -eq 'Integrity') { $mt = 'Clean-Check'; $mf = 'Integritaet' }
        $base = Join-Path $rdir ('Karito-PC-Check_' + $mf + '_' + (Get-Date -Format 'yyyy-MM-dd_HH-mm'))
        $osx = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
        $osTxt = ''; if ($osx) { $osTxt = "$($osx.Caption) ($($osx.BuildNumber))" }
        $lab = @{ crit = 'KRITISCH'; warn = 'AUFFÄLLIG'; info = 'HINWEIS'; ok = 'OK' }
        $vcol = '#34d399'; if ($verdict -in 'PRÜFEN', 'GUT') { $vcol = '#fbbf24' } elseif ($verdict -in 'KRITISCH', 'AUSBAUFÄHIG') { $vcol = '#f87171' }
        $now = (Get-Date).ToString('dd.MM.yyyy HH:mm')
        $hb = New-Object System.Text.StringBuilder
        [void]$hb.Append('<!DOCTYPE html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Karito Scanner – Bericht</title><style>')
        [void]$hb.Append('body{margin:0;background:#07070a;color:#f1f1f5;font:14px/1.5 "Segoe UI",system-ui,sans-serif;padding:32px 18px}.w{max-width:940px;margin:0 auto}h1{font-size:26px;margin:0 0 4px}h2{font-size:17px;margin:24px 0 6px}.m{color:#8d8d9b}.v{display:inline-block;margin:18px 0 8px;padding:12px 24px;border-radius:16px;font-weight:800;font-size:24px;letter-spacing:.08em;border:2px solid}.box{background:#111116;border:1px solid rgba(255,255,255,.08);border-radius:16px;padding:6px 16px;margin:12px 0}table{width:100%;border-collapse:collapse}td{padding:10px 8px;border-top:1px solid rgba(255,255,255,.06);vertical-align:top}tr:first-child td{border-top:0}.s{font:700 11px/1 Consolas,monospace;padding:5px 8px;border-radius:7px;white-space:nowrap}.crit{background:rgba(248,113,113,.15);color:#f87171}.warn{background:rgba(251,191,36,.15);color:#fbbf24}.info{background:rgba(255,255,255,.07);color:#b3b3bf}.ok{background:rgba(52,211,153,.13);color:#34d399}.d{color:#8d8d9b;font:12px/1.5 Consolas,monospace;word-break:break-all;margin-top:2px}.c{color:#8d8d9b;font-size:12px;white-space:nowrap}.f{color:#5f5f6d;font-size:12px}')
        [void]$hb.Append('</style></head><body><div class="w">')
        [void]$hb.Append(('<h1>&#9650; Karito Scanner – {0}</h1><div class="m">Erstellt am {1} · {2} · Engine {3}</div>' -f (HtmlE $mt), (HtmlE $now), (HtmlE $osTxt), (HtmlE $Version)))
        [void]$hb.Append(('<div class="v" style="color:{0};border-color:{0}">{1}</div>' -f $vcol, (HtmlE $verdict)))
        if ($Mode -eq 'Integrity') { [void]$hb.Append(('<div class="m">Risiko: <b style="color:{0}">{1}</b> · Bereinigungs-Spuren: <b>{2}</b> ({3} Punkte)</div>' -f $vcol, (HtmlE $risk), (HtmlE $cleanLvl), $cpts)) }
        [void]$hb.Append(('<div class="m">{0} Punkte · {1} kritisch · {2} auffällig · {3} Prüfpunkte</div><div class="box"><table>' -f $score, $crit, $warn, $scanItems.Count))
        foreach ($sv2 in 'crit', 'warn', 'info', 'ok') {
          foreach ($it in @($scanItems | Where-Object { $_.sev -eq $sv2 })) {
            $dx = [string]$it.detail; if ($it.ref) { $dx += ' · SHA-256 ' + $it.ref }
            [void]$hb.Append(('<tr><td><span class="s {0}">{1}</span></td><td><b>{2}</b><div class="d">{3}</div></td><td class="c">{4}</td></tr>' -f $sv2, $lab[$sv2], (HtmlE $it.title), (HtmlE $dx), (HtmlE $it.cat)))
          }
        }
        [void]$hb.Append('</table></div>')
        if ($tline.Count) {
          [void]$hb.Append('<h2>Zeitleiste</h2><div class="box"><table>')
          foreach ($ev2 in $tline) { $tdt = ([datetime]$ev2.t).ToString('dd.MM.yyyy HH:mm'); [void]$hb.Append(('<tr><td class="c">{0}</td><td class="c">{1}</td><td>{2}</td></tr>' -f (HtmlE $tdt), (HtmlE $ev2.src), (HtmlE $ev2.text))) }
          [void]$hb.Append('</table></div>')
        }
        [void]$hb.Append('<p class="f">Der Scan lief nur lokal auf diesem PC, es wurde nichts hochgeladen. Er zeigt Hinweise, keine Beweise – jeder Treffer sollte selbst geprüft werden.</p></div></body></html>')
        [System.IO.File]::WriteAllText($base + '.html', $hb.ToString(), (New-Object System.Text.UTF8Encoding $true))
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine("Karito Scanner – $mt")
        [void]$sb.AppendLine("Erstellt: $now · $osTxt · Engine $Version")
        [void]$sb.AppendLine("Urteil: $verdict · $score Punkte · $crit kritisch · $warn auffällig")
        if ($Mode -eq 'Integrity') { [void]$sb.AppendLine("Risiko: $risk · Bereinigungs-Spuren: $cleanLvl ($cpts Punkte)") }
        [void]$sb.AppendLine('')
        foreach ($sv2 in 'crit', 'warn', 'info', 'ok') {
          foreach ($it in @($scanItems | Where-Object { $_.sev -eq $sv2 })) {
            $line = "[$($lab[$sv2])] $($it.title)"
            if ($it.detail) { $line += " – $($it.detail)" }
            if ($it.ref) { $line += " – SHA-256 $($it.ref)" }
            [void]$sb.AppendLine($line)
          }
        }
        if ($tline.Count) {
          [void]$sb.AppendLine(''); [void]$sb.AppendLine('Zeitleiste:')
          foreach ($ev2 in $tline) { [void]$sb.AppendLine("  $(([datetime]$ev2.t).ToString('dd.MM.yyyy HH:mm'))  [$($ev2.src)]  $($ev2.text)") }
        }
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('Hinweis: Der Scan zeigt Hinweise, keine Beweise. Er lief nur lokal, es wurde nichts hochgeladen.')
        [System.IO.File]::WriteAllText($base + '.txt', $sb.ToString(), (New-Object System.Text.UTF8Encoding $true))
        # nur die neuesten 20 Berichte behalten (je HTML + TXT)
        Get-ChildItem -LiteralPath $rdir -File -Filter 'Karito-PC-Check_*' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -Skip 40 | Remove-Item -Force -ErrorAction SilentlyContinue
        $report = $base + '.html'; $reportTxt = $base + '.txt'
        Say "Bericht gespeichert: $report" 'ok'
      }
      $Data = @{ mode = $Mode; score = $score; verdict = $verdict; risk = $risk; cleaning = @{ level = $cleanLvl; points = $cpts }; crit = $crit; warn = $warn; items = @($scanItems); timeline = $tline; report = $report; reportTxt = $reportTxt; time = (Get-Date).ToString('s') }
    }
  }
} catch {
  $OK = $false
  Say $_.Exception.Message 'err'
}

if ($Json) {
  [Console]::Out.Write((@{ ok = $OK; log = @($Log); data = $Data } | ConvertTo-Json -Depth 14 -Compress))
} elseif ($Data -and ($Command -in 'List', 'Status', 'StartupList', 'Hwid')) {
  $Data | ConvertTo-Json -Depth 6
}
if (-not $OK) { exit 1 }
