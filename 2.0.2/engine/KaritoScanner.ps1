<#
  Karito Tweaks - Scanner 2.0.0 (Clean-Check)
  Wird von KaritoEngine.ps1 nur für den Clean-Check und den Selbsttest geladen.
  Liest ausschließlich Spuren aus und ändert nichts am System. Die Suchbegriffe stehen als Daten in tweaks.json.
#>
$ScannerVersion = '2.0.0'
$ScanCfg = $Cat.scanner
$KwCrit = @(@($ScanCfg.kwCrit) + @($Strings) | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLower() })   # eigene Suchbegriffe gelten als kritisch
$KwWarn = @($ScanCfg.kwWarn | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLower() })
$KwTools = @($ScanCfg.kwTools | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLower() })
$ScanCrit = @($ScanCfg.crit | Where-Object { $_ })
$ScanNeedles = @(@($ScanCfg.apis) + $ScanCrit | Where-Object { $_ })
$DnsRx = [string]$ScanCfg.dns; if (-not $DnsRx) { $DnsRx = '^$' }
$HostsRx = [string]$ScanCfg.hosts; if (-not $HostsRx) { $HostsRx = '^$' }
$ThreatRx = [string]$ScanCfg.threat

function UsnLoad {
  if ('KaritoUsn' -as [type]) { return }
  $cs = [System.IO.File]::ReadAllText((Join-Path $PSScriptRoot 'KaritoScanner.cs'))
  Add-Type -TypeDefinition $cs -Language CSharp -ErrorAction Stop | Out-Null
}
function KwLevel($s) {
  $nm = ([string]$s).ToLower()
  foreach ($k in $KwTools) { if ($nm.Contains($k)) { return 'info' } }
  foreach ($k in $KwCrit) { if ($nm.Contains($k)) { return 'crit' } }
  foreach ($k in $KwWarn) { if ($nm.Contains($k)) { return 'warn' } }
  $null
}
function Prog($key, $label) { if ($Json) { try { [Console]::Out.WriteLine('@@P|' + $key + '|' + $label); [Console]::Out.Flush() } catch {} } }
function TL($when, $src, $text, $sev) { if (-not $when) { return }; try { [void]$script:timeline.Add(@{ t = ([datetime]$when).ToString('s'); src = [string]$src; text = [string]$text; sev = [string]$sev }) } catch {} }
function CleanHit($hid, $sev, $title, $detail, $pts) { $script:cleanPts += [int]$pts; Hit $hid 'Bereinigung' $sev $title $detail '' '' }
function MapDrives { , @([System.IO.DriveInfo]::GetDrives() | Where-Object { $_.IsReady -and ($_.DriveType -eq 'Fixed' -or $_.DriveType -eq 'Removable') } | ForEach-Object { $_.Name.Substring(0, 2) }) }
function Route($path) {
  # Typische Umgehungswege: Start direkt aus einem Archiv, vom Netzwerk, von USB oder von einem getrennten Laufwerk
  $rp = [string]$path
  if ($rp -match '\\Rar\$[A-Za-z]{2}' -or $rp -match '\\7z[A-Za-z0-9]{3,}\\' -or $rp -match '\\Temp\d*_[^\\]+\.(zip|rar|7z)\\') { return 'Archiv' }
  if ($rp.StartsWith('\\') -or $rp -match '^\\Device\\Mup\\') { return 'Netzwerk' }
  if ($rp -match '^\\Device\\HarddiskVolume\d+\\' -and $devMap.Count -gt 0) { return 'Getrennt' }
  if ($rp.Length -ge 2 -and $remDrives -contains $rp.Substring(0, 2).ToUpper()) { return 'USB' }
  $null
}
function RouteName($r) { switch ($r) { 'Archiv' { 'einem Archiv' } 'Netzwerk' { 'einem Netzlaufwerk' } 'USB' { 'einem USB-Laufwerk' } 'Getrennt' { 'einem nicht mehr verbundenen Laufwerk' } default { [string]$r } } }

function Test-KaritoScanner {
  # Selbsttest: Daten vorhanden, C#-Modul kompiliert, Datei-Analyse an einer echten Windows-Datei
  if (-not $ScanNeedles.Count -or -not $KwCrit.Count) { throw 'Scanner-Daten fehlen im Katalog.' }
  UsnLoad
  $kdll = Join-Path $env:SystemRoot 'System32\kernel32.dll'
  $ptest = ([string][KaritoUsn]::PeInfo($kdll, 4194304, [string[]]@('GetProcAddress'))).Split([char[]]@('|'), 4)
  if ($ptest.Count -ne 4 -or $ptest[1] -notmatch '\.text') { throw "Datei-Analyse lieferte unerwartete Werte ($($ptest -join '|'))." }
  "Scanner-Modul OK: Datei-Analyse und NTFS-Journal einsatzbereit (Scanner $ScannerVersion)"
}

function Invoke-KaritoIntegrity {
        # ===== Clean-Check (forensisch, nur lesend) =====
        $script:timeline = New-Object System.Collections.ArrayList
        $script:cleanPts = 0
        $userRuns = New-Object System.Collections.ArrayList
        $susp = New-Object System.Collections.ArrayList
        $remDrives = @([System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Removable' -and $_.IsReady } | ForEach-Object { $_.Name.Substring(0, 2).ToUpper() })
        $instDate = $null; $build = 0
        try { $osi = Get-CimInstance Win32_OperatingSystem; $instDate = $osi.InstallDate; $build = [int]$osi.BuildNumber } catch {}

        Prog 'boot' 'Startoptionen'
        $opts = [string](Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name SystemStartOptions -ErrorAction SilentlyContinue).SystemStartOptions
        if ($opts -match 'TESTSIGNING') { Hit 'testsign' 'Startoptionen' 'crit' 'Testsignatur-Modus aktiv' 'Erlaubt das Laden unsignierter Treiber.' '' }
        if ($opts -match 'DISABLE_INTEGRITY_CHECKS') { Hit 'nointegrity' 'Startoptionen' 'crit' 'Treiber-Signaturprüfung abgeschaltet' '' '' }
        if ($opts -match '\bDEBUG\b') { Hit 'kdebug' 'Startoptionen' 'warn' 'Kernel-Debugging aktiv' '' '' }
        if (-not @($scanItems | Where-Object { $_.cat -eq 'Startoptionen' }).Count) { Hit 'bootok' 'Startoptionen' 'ok' 'Keine verdächtigen Startoptionen' 'Testsignatur, Signaturprüfung und Kernel-Debugging sind normal.' '' }

        Prog 'services' 'Spuren-Dienste'
        $core = @('SysMain', 'PcaSvc', 'EventLog', 'DPS')
        $svcBad = 0
        foreach ($pn2 in $ProtNames) {
          $s2 = Get-CimInstance Win32_Service -Filter "Name='$pn2'" -ErrorAction SilentlyContinue
          if (-not $s2) { continue }
          if ($s2.StartMode -eq 'Disabled') {
            $sv3 = 'warn'; $pts = 1; if ($core -contains $pn2) { $sv3 = 'crit'; $pts = 3 }
            CleanHit "svc:$pn2" $sv3 "Dienst „$($Protected[$pn2])“ ist deaktiviert" 'Wird oft abgeschaltet, damit keine Spuren entstehen.' $pts; $svcBad++
          } elseif ($s2.State -ne 'Running') { CleanHit "svc:$pn2" 'warn' "Dienst „$($Protected[$pn2])“ läuft nicht" 'Spuren-Dienste sollten laufen.' 1; $svcBad++ }
        }
        if (-not $svcBad) { Hit 'svcok' 'Dienste' 'ok' 'Alle 8 Spuren-Dienste laufen' 'SysMain, DNS-Client, Datennutzung, Diagnose, Ereignisprotokoll, PCA, Telemetrie, verbundene Geräte' '' }
        $bamd = Get-CimInstance Win32_SystemDriver -Filter "Name='bam'" -ErrorAction SilentlyContinue
        if ($bamd -and ($bamd.State -ne 'Running' -or $bamd.StartMode -eq 'Disabled')) { CleanHit 'bamoff' 'crit' 'BAM-Protokollierung ist aus' 'Damit werden Programmstarts nicht mehr aufgezeichnet.' 3 }

        Prog 'prefetch' 'Prefetch'
        $pfOn = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -Name EnablePrefetcher -ErrorAction SilentlyContinue).EnablePrefetcher
        if ($null -ne $pfOn -and $pfOn -eq 0) { CleanHit 'pfoff' 'crit' 'Prefetch ist abgeschaltet' 'Damit werden keine Programmstarts mehr protokolliert.' 3 }
        $pfl = @(Get-ChildItem -LiteralPath (Join-Path $env:SystemRoot 'Prefetch') -Filter '*.pf' -Force -ErrorAction SilentlyContinue)
        if ($pfl.Count -lt 30) { CleanHit 'pfempty' 'warn' "Nur $($pfl.Count) Prefetch-Einträge" 'Der Ordner wurde womöglich kürzlich geleert.' 2 }
        else {
          Hit 'pfcount' 'Spuren' 'ok' "$($pfl.Count) Prefetch-Einträge vorhanden" '' ''
          $oldest = ($pfl | Sort-Object LastWriteTime | Select-Object -First 1).LastWriteTime
          if ($instDate -and $instDate -lt (Get-Date).AddDays(-7) -and $oldest -gt (Get-Date).AddDays(-2)) { CleanHit 'pffresh' 'warn' 'Prefetch enthält nur Einträge der letzten 2 Tage' 'Der Ordner wurde womöglich kürzlich geleert.' 2 }
        }
        foreach ($pf in $pfl) {
          $exe = $pf.Name -replace '-[0-9A-Fa-f]{8}\.pf$', ''
          $lv = KwLevel $exe
          if ($lv) { Hit "pf:$exe" 'Programmstarts' $lv "$exe wurde ausgeführt" "Prefetch · zuletzt $($pf.LastWriteTime.ToString('dd.MM.yyyy HH:mm'))" ''; TL $pf.LastWriteTime 'Prefetch' "$exe ausgeführt" $lv }
        }

        Prog 'journal' 'NTFS-Journal'
        $devMap = @{}
        $usnOk = $false
        try { UsnLoad; $usnOk = $true } catch { Hit 'usnna' 'Spuren' 'info' 'Journal-Prüfung nicht verfügbar' ([string]$_.Exception.Message) '' }
        if ($usnOk) {
          foreach ($dl2 in (MapDrives)) { try { $dd = [KaritoUsn]::DosDevice($dl2); if ($dd) { $devMap[$dd] = $dl2 } } catch {} }
          try {
            $ft = [long]0
            $rows = [KaritoUsn]::Read('C:', 7, [string[]]@('.exe', '.dll', '.sys', '.ahk', '.lua', '.bat', '.pf', '.dmp'), [ref]$ft)
            $delExe = 0; $delPf = 0
            foreach ($row in $rows) {
              $pp3 = ([string]$row).Split([char[]]@('|'), 3)
              if ($pp3.Count -lt 3) { continue }
              $wdt = [DateTime]::FromFileTimeUtc([long]$pp3[0]).ToLocalTime()
              $rs = [int64]$pp3[1]; $fnm = [string]$pp3[2]
              $isDel = [bool]($rs -band 0x200)
              $what = 'umbenannt'; if ($isDel) { $what = 'gelöscht' }
              $isPf = $fnm -match '\.pf$'
              $lv = KwLevel ($fnm -replace '-[0-9A-Fa-f]{8}\.pf$', '')
              if ($lv) {
                if ($isPf -and $isDel) { $lv = 'crit' }
                Hit "usn:$fnm" 'Gelöschte Dateien' $lv "$fnm wurde $what" "NTFS-Journal · $($wdt.ToString('dd.MM.yyyy HH:mm'))" ''
                TL $wdt 'NTFS-Journal' "$fnm $what" $lv
              } elseif ($isDel) { if ($isPf) { $delPf++ } else { $delExe++ } }
            }
            if ($delExe) { Hit 'usndel' 'Gelöschte Dateien' 'info' "$delExe Programmdateien in den letzten 7 Tagen gelöscht" 'Laut NTFS-Journal – meist Updates und Installer.' '' }
            if ($delPf -gt 60) { CleanHit 'usnpf' 'warn' "$delPf Prefetch-Dateien in den letzten 7 Tagen gelöscht" 'Ungewöhnlich viele – typisch für das Leeren von Spuren.' 2 }
            if ($ft -gt 0) {
              $jage = ((Get-Date) - [DateTime]::FromFileTimeUtc($ft).ToLocalTime()).TotalHours
              if ($jage -lt 24) { CleanHit 'usnfresh' 'warn' 'NTFS-Journal reicht keine 24 Stunden zurück' 'Es wurde womöglich gelöscht – bei sehr aktiven PCs kann das auch normal sein.' 2 }
              else { Hit 'usnage' 'Spuren' 'ok' "NTFS-Journal reicht $([math]::Round($jage / 24, 1)) Tage zurück" '' '' }
            }
          } catch {
            if ([string]$_.Exception.Message -match '1179') { CleanHit 'usnoff' 'crit' 'NTFS-Journal ist deaktiviert' 'Damit werden Datei-Änderungen nicht mehr protokolliert.' 3 }
            else { Hit 'usnerr' 'Spuren' 'info' 'NTFS-Journal konnte nicht gelesen werden' ([string]$_.Exception.Message) '' }
          }
        }

        Prog 'bam' 'Programmstarts (BAM)'
        $tempRuns = New-Object System.Collections.ArrayList
        try {
          foreach ($uk in @(Get-ChildItem -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings' -ErrorAction Stop)) {
            $bk2 = Get-Item -LiteralPath $uk.PSPath
            foreach ($vn in @($bk2.GetValueNames())) {
              if ($vn -notmatch '\.exe$') { continue }
              $full = $vn
              foreach ($dk2 in @($devMap.Keys)) { if ($vn.StartsWith($dk2 + '\', [StringComparison]::OrdinalIgnoreCase)) { $full = $devMap[$dk2] + $vn.Substring($dk2.Length); break } }
              $leaf = ($vn -split '\\')[-1]
              $when = $null; $raw2 = $bk2.GetValue($vn)
              if ($raw2 -is [byte[]] -and $raw2.Length -ge 8) { try { $when = [DateTime]::FromFileTime([BitConverter]::ToInt64($raw2, 0)) } catch {} }
              $wtxt = ''; if ($when) { $wtxt = $when.ToString('dd.MM.yyyy HH:mm') }
              $lv = KwLevel $leaf
              $rt = Route $full
              if ($lv) { Hit "bam:$leaf" 'Programmstarts' $lv "$leaf gestartet" "BAM · $wtxt · $full" ''; TL $when 'BAM' "$leaf gestartet" $lv; [void]$susp.Add($full) }
              elseif ($rt) { Hit "route:$leaf" 'Umgehungswege' 'warn' "$leaf direkt aus $(RouteName $rt) gestartet" "BAM · $wtxt · $full" ''; TL $when 'BAM' "$leaf aus $(RouteName $rt) gestartet" 'warn'; [void]$susp.Add($full) }
              else {
                if ($full -match '\\(Temp|Downloads)\\') { [void]$tempRuns.Add($leaf) }
                if ($full -match '\\Users\\') { [void]$userRuns.Add($full) }
              }
            }
          }
        } catch {}
        if ($tempRuns.Count) { $tl2 = @($tempRuns | Select-Object -Unique); Hit 'bamtemp' 'Programmstarts' 'info' "$($tl2.Count) Programme aus Downloads/Temp gestartet" (($tl2 | Select-Object -First 8) -join ', ') '' }

        Prog 'pca' 'PCA-Protokoll'
        try {
          $pca = Join-Path $env:SystemRoot 'appcompat\pca\PcaAppLaunchDic.txt'
          if (Test-Path -LiteralPath $pca) {
            $pb = [System.IO.File]::ReadAllBytes($pca)
            if ($pb.Length -ge 4 -and (($pb[0] -eq 0xFF -and $pb[1] -eq 0xFE) -or ($pb[1] -eq 0 -and $pb[3] -eq 0))) { $ptxt = [System.Text.Encoding]::Unicode.GetString($pb) } else { $ptxt = [System.Text.Encoding]::UTF8.GetString($pb) }
            $pcaN = 0
            foreach ($pl2 in ($ptxt -split "`r?`n")) {
              $pt = $pl2.Trim([char]0xFEFF, [char]0, [char]32)
              if (-not $pt) { continue }
              $parts = $pt.Split([char[]]@('|'), 2)
              $pcaN++
              $pathP = $parts[0]; $wP = $null; $wt = ''
              if ($parts.Count -gt 1) { $wt = $parts[1].Trim(); try { $wP = [datetime]::Parse($wt, [Globalization.CultureInfo]::InvariantCulture) } catch {} }
              $leaf = ($pathP -split '\\')[-1]
              $lv = KwLevel $leaf
              $rt = Route $pathP
              if ($lv) { Hit "pca:$leaf" 'Programmstarts' $lv "$leaf gestartet" "PCA · $wt · $pathP" ''; TL $wP 'PCA' "$leaf gestartet" $lv; [void]$susp.Add($pathP) }
              elseif ($rt) { Hit "route:$leaf" 'Umgehungswege' 'warn' "$leaf direkt aus $(RouteName $rt) gestartet" "PCA · $wt · $pathP" ''; TL $wP 'PCA' "$leaf aus $(RouteName $rt) gestartet" 'warn'; [void]$susp.Add($pathP) }
              elseif ($pathP -match '\\Users\\') { [void]$userRuns.Add($pathP) }
            }
            if ($pcaN) { Hit 'pcacount' 'Spuren' 'ok' "$pcaN Programmstarts im PCA-Protokoll" '' '' }
            else { CleanHit 'pcaempty' 'warn' 'PCA-Protokoll ist leer' 'Die Datei wurde womöglich geleert.' 2 }
          } elseif ($build -ge 22621 -and $instDate -and $instDate -lt (Get-Date).AddDays(-7)) { CleanHit 'pcamissing' 'warn' 'PCA-Protokoll fehlt' 'Unter Windows 11 sollte es existieren – womöglich gelöscht.' 2 }
        } catch {}

        Prog 'shim' 'Kompatibilitäts-Historie'
        try {
          $ac = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache' -Name AppCompatCache -ErrorAction Stop).AppCompatCache
          if ($ac -is [byte[]] -and $ac.Length -gt 64) {
            $pos = [BitConverter]::ToInt32($ac, 0); $cnt = 0
            while ($pos -gt 0 -and $pos + 14 -lt $ac.Length -and $cnt -lt 3000) {
              if ([System.Text.Encoding]::ASCII.GetString($ac, $pos, 4) -ne '10ts') { break }
              $dsz = [BitConverter]::ToInt32($ac, $pos + 8)
              $plen = [BitConverter]::ToUInt16($ac, $pos + 12)
              if ($plen -gt 0 -and $pos + 14 + $plen -le $ac.Length) {
                $spath = [System.Text.Encoding]::Unicode.GetString($ac, $pos + 14, $plen)
                $leaf = ($spath -split '\\')[-1]
                $lv = KwLevel $leaf
                $rt = Route $spath
                if ($lv) { Hit "shim:$leaf" 'Programmspuren' $lv "$leaf in der Kompatibilitäts-Historie" $spath ''; [void]$susp.Add($spath) }
                elseif ($rt) { Hit "route:$leaf" 'Umgehungswege' 'warn' "$leaf lief aus $(RouteName $rt)" "Kompatibilitäts-Historie · $spath" '' }
                elseif ($spath -match '\\Users\\') { [void]$userRuns.Add($spath) }
              }
              if ($dsz -le 0) { break }
              $pos += 12 + $dsz; $cnt++
            }
            Hit 'shimcount' 'Spuren' 'ok' "$cnt Einträge in der Kompatibilitäts-Historie" '' ''
          }
        } catch {}

        Prog 'recycle' 'Papierkorb'
        $rbOther = New-Object System.Collections.ArrayList
        try {
          $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
          foreach ($drv in (FixedDrives)) {
            $rb = Join-Path ($drv + '\') ('$Recycle.Bin\' + $sid)
            if (-not (Test-Path -LiteralPath $rb)) { continue }
            foreach ($ifile in @(Get-ChildItem -LiteralPath $rb -Filter '$I*' -Force -ErrorAction SilentlyContinue)) {
              try {
                $ib = [System.IO.File]::ReadAllBytes($ifile.FullName)
                if ($ib.Length -lt 28) { continue }
                $ver = [BitConverter]::ToInt64($ib, 0)
                $del = [DateTime]::FromFileTime([BitConverter]::ToInt64($ib, 16))
                if ($ver -ge 2) { $len = [BitConverter]::ToInt32($ib, 24); $orig = [System.Text.Encoding]::Unicode.GetString($ib, 28, [math]::Min($len * 2, $ib.Length - 28)).TrimEnd([char]0) }
                else { $orig = [System.Text.Encoding]::Unicode.GetString($ib, 24, [math]::Min(520, $ib.Length - 24)).TrimEnd([char]0) }
                if ($orig -notmatch '\.(exe|dll|sys|lua|ahk|bat|zip|rar|7z)$') { continue }
                $leaf = ($orig -split '\\')[-1]
                $lv = KwLevel $leaf
                if ($lv) { Hit "rb:$leaf" 'Gelöschte Dateien' $lv "$leaf im Papierkorb" "Gelöscht am $($del.ToString('dd.MM.yyyy HH:mm')) · $orig" ''; TL $del 'Papierkorb' "$leaf gelöscht" $lv }
                else { [void]$rbOther.Add($leaf) }
              } catch {}
            }
          }
        } catch {}
        if ($rbOther.Count) { Hit 'rbother' 'Gelöschte Dateien' 'info' "$($rbOther.Count) Programme oder Archive im Papierkorb" ((@($rbOther) | Select-Object -First 8) -join ', ') '' }

        Prog 'recent' 'Zuletzt geöffnet'
        foreach ($lnk in @(Get-ChildItem -LiteralPath (Join-Path $env:APPDATA 'Microsoft\Windows\Recent') -Filter '*.lnk' -Force -ErrorAction SilentlyContinue)) {
          $lv = KwLevel $lnk.BaseName
          # Nur Programme und Archive – ein Dokument „Cheat Sheet.pdf“ ist kein Treffer
          if ($lv -and ($lv -eq 'crit' -or $lnk.BaseName -match '\.(exe|zip|rar|7z|dll|lua|ahk|bat)$')) { Hit "recent:$($lnk.BaseName)" 'Zuletzt geöffnet' $lv "$($lnk.BaseName) wurde geöffnet" "Am $($lnk.LastWriteTime.ToString('dd.MM.yyyy HH:mm'))" ''; TL $lnk.LastWriteTime 'Zuletzt geöffnet' "$($lnk.BaseName) geöffnet" $lv }
        }

        Prog 'logs' 'Ereignisprotokolle'
        foreach ($lg in @(@{ n = 'System'; i = 104 }, @{ n = 'Security'; i = 1102 })) {
          try {
            foreach ($ev in @(Get-WinEvent -FilterHashtable @{ LogName = $lg.n; Id = $lg.i } -MaxEvents 3 -ErrorAction Stop)) {
              if ($ev.TimeCreated -gt (Get-Date).AddDays(-30)) { CleanHit "log:$($lg.n):$($ev.RecordId)" 'warn' "Ereignisprotokoll „$($lg.n)“ wurde gelöscht" "Am $($ev.TimeCreated.ToString('dd.MM.yyyy HH:mm'))" 3; TL $ev.TimeCreated 'Ereignisprotokoll' "Protokoll $($lg.n) gelöscht" 'warn' }
            }
          } catch {}
        }
        try {
          foreach ($tev in @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4616; StartTime = (Get-Date).AddDays(-14) } -MaxEvents 30 -ErrorAction Stop)) {
            $tpn = [string]$tev.Properties[7].Value
            if ($tpn -and $tpn -notmatch '\\(svchost|w32tm)\.exe$') { CleanHit "time:$($tev.RecordId)" 'warn' 'Systemzeit wurde manuell geändert' "Am $($tev.TimeCreated.ToString('dd.MM.yyyy HH:mm')) durch $tpn" 2; TL $tev.TimeCreated 'Systemzeit' 'Uhrzeit manuell geändert' 'warn'; break }
          }
        } catch {}

        Prog 'defender' 'Virenschutz'
        try {
          $mp = Get-MpPreference -ErrorAction Stop
          foreach ($exn in @(@($mp.ExclusionPath) + @($mp.ExclusionProcess) | Where-Object { $_ -and $_ -notmatch '^N/A' })) {
            $sev = 'info'; if ($exn -match '\\(Users|Temp|Downloads|AppData|Desktop)\\' -or (KwLevel $exn)) { $sev = 'warn' }
            Hit "mp:$exn" 'Virenschutz' $sev "Defender-Ausnahme: $exn" 'Über Ausnahmen werden Cheat-Programme oft am Virenschutz vorbeigeschleust.' ''
          }
        } catch {}
        try {
          $thrMap = @{}
          foreach ($tt in @(Get-MpThreat -ErrorAction Stop)) { $thrMap[[string]$tt.ThreatID] = [string]$tt.ThreatName }
          foreach ($det in @(Get-MpThreatDetection -ErrorAction Stop | Sort-Object InitialDetectionTime -Descending | Select-Object -First 40)) {
            $tn = $thrMap[[string]$det.ThreatID]; if (-not $tn) { $tn = "Bedrohung $($det.ThreatID)" }
            $resP = ([string](@($det.Resources) | Select-Object -First 1)) -replace '^[a-z]+:_', ''
            $sev = 'warn'; if ($ThreatRx -and $tn -match $ThreatRx) { $sev = 'crit' }
            $dt = $det.InitialDetectionTime; $dtx = ''; if ($dt) { $dtx = ([datetime]$dt).ToString('dd.MM.yyyy HH:mm') }
            Hit "mpdet:$($det.DetectionID)" 'Virenschutz' $sev "Defender hat $tn erkannt" "$dtx · $resP" ''
            TL $dt 'Defender' "$tn erkannt" $sev
          }
        } catch {}
        if (-not @($scanItems | Where-Object { $_.cat -eq 'Virenschutz' }).Count) { Hit 'mpok' 'Virenschutz' 'ok' 'Keine Defender-Ausnahmen oder -Funde' '' '' }

        Prog 'drivers' 'Treiber'
        try {
          foreach ($dr in @(Get-CimInstance Win32_SystemDriver -Filter "State='Running'" -ErrorAction Stop)) {
            $pth = [string]$dr.PathName
            if ($pth -match '\\(Users|Temp|Downloads|AppData)\\') { Hit "drv:$($dr.Name)" 'Treiber' 'crit' "Treiber aus Benutzerordner geladen: $($dr.Name)" $pth ''; [void]$susp.Add($pth) }
            elseif ((KwLevel $dr.Name) -eq 'crit') { Hit "drv:$($dr.Name)" 'Treiber' 'crit' "Verdächtiger Treiber geladen: $($dr.Name)" $pth '' }
          }
        } catch {}
        if (-not @($scanItems | Where-Object { $_.cat -eq 'Treiber' }).Count) { Hit 'drvok' 'Treiber' 'ok' 'Keine verdächtigen Treiber geladen' '' '' }

        Prog 'hardware' 'Hardware'
        try { foreach ($pd in @(Get-PnpDevice -PresentOnly -ErrorAction Stop | Where-Object { $_.InstanceId -match 'VID_0403&PID_601F' })) { Hit "dma:$($pd.InstanceId)" 'Hardware' 'warn' 'USB-Gerät mit FT601-Chip angeschlossen' 'Dieser Chip steckt oft in DMA-Karten – kann aber auch legitime FPGA-Hardware sein.' '' } } catch {}
        try {
          $usbn = @()
          foreach ($uk2 in @(Get-ChildItem -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR' -ErrorAction Stop)) {
            foreach ($ik in @(Get-ChildItem -LiteralPath $uk2.PSPath -ErrorAction SilentlyContinue)) {
              $fn = (Get-ItemProperty -LiteralPath $ik.PSPath -Name FriendlyName -ErrorAction SilentlyContinue).FriendlyName
              if ($fn) { $usbn += [string]$fn }
            }
          }
          $usbn = @($usbn | Select-Object -Unique)
          if ($usbn.Count) { Hit 'usbhist' 'Hardware' 'info' "$($usbn.Count) USB-Speicher waren schon verbunden" (($usbn | Select-Object -First 6) -join ', ') '' }
        } catch {}
        try { $cs2 = Get-CimInstance Win32_ComputerSystem; if ("$($cs2.Manufacturer) $($cs2.Model)" -match 'VMware|VirtualBox|Virtual Machine|QEMU|KVM|Xen|Parallels') { Hit 'vm' 'Hardware' 'warn' 'Der Scan läuft in einer virtuellen Maschine' "$($cs2.Manufacturer) $($cs2.Model)" '' } } catch {}

        Prog 'network' 'Netzwerk'
        try {
          foreach ($hl in @(Get-Content -LiteralPath (Join-Path $env:SystemRoot 'System32\drivers\etc\hosts') -ErrorAction Stop)) {
            $hx = $hl.Trim(); if (-not $hx -or $hx.StartsWith('#')) { continue }
            if ($hx -match $HostsRx) { Hit "hosts:$hx" 'Netzwerk' 'crit' 'hosts-Datei blockiert Anti-Cheat- oder FiveM-Server' $hx '' }
          }
        } catch {}
        try {
          foreach ($dc in @(Get-DnsClientCache -ErrorAction Stop)) {
            $dn = [string]$dc.Entry
            # bewusst nur eindeutige Begriffe – sonst wären z. B. Entwickler-Seiten Treffer
            if ($dn -match $DnsRx) { Hit "dns:$dn" 'Netzwerk' 'warn' "Kürzlich aufgerufen: $dn" 'Aus dem DNS-Zwischenspeicher von Windows.' '' }
          }
        } catch {}

        Prog 'processes' 'Laufende Programme'
        foreach ($pr in @(Get-Process -ErrorAction SilentlyContinue)) {
          $lv = KwLevel $pr.Name
          if ($lv) { $pp5 = ''; try { $pp5 = [string]$pr.Path } catch {}; Hit "proc:$($pr.Name)" 'Laufende Programme' $lv "$($pr.Name) läuft gerade" $pp5 ''; if ($pp5) { [void]$susp.Add($pp5) } }
        }

        Prog 'games' 'Spielordner'
        try {
          $fvm = Join-Path $env:LOCALAPPDATA 'FiveM\FiveM.app'
          if (Test-Path -LiteralPath $fvm) {
            $plg = Join-Path $fvm 'plugins'
            if (Test-Path -LiteralPath $plg) {
              $pf2 = @(Get-ChildItem -LiteralPath $plg -Recurse -Force -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -match '^\.(asi|dll|exe|lua)$' })
              foreach ($f3 in $pf2) { $sev = 'warn'; if ((KwLevel $f3.Name) -eq 'crit') { $sev = 'crit' }; Hit "fivemplg:$($f3.Name)" 'FiveM' $sev "Programmdatei im FiveM-Plugin-Ordner: $($f3.Name)" "$($f3.FullName) · $($f3.LastWriteTime.ToString('dd.MM.yyyy HH:mm'))" ''; [void]$susp.Add($f3.FullName) }
              if (-not $pf2.Count) { Hit 'fivemplgok' 'FiveM' 'ok' 'FiveM-Plugin-Ordner ohne Programmdateien' '' '' }
            } else { Hit 'fivemplgok' 'FiveM' 'ok' 'Kein FiveM-Plugin-Ordner vorhanden' '' '' }
            $mods = Join-Path $fvm 'mods'
            if (Test-Path -LiteralPath $mods) { $mc = @(Get-ChildItem -LiteralPath $mods -Force -File -ErrorAction SilentlyContinue).Count; if ($mc) { Hit 'fivemmods' 'FiveM' 'info' "$mc Dateien im FiveM-Mods-Ordner" 'Grafik- und Sound-Mods sind oft erlaubt – prüfe die Server-Regeln.' '' } }
          }
          $gx = ExeTargets @('*:\Program Files\Rockstar Games\Grand Theft Auto V\GTA5.exe', '*:\Program Files\Rockstar Games\Grand Theft Auto V Enhanced\GTA5_Enhanced.exe', '*:\Program Files (x86)\Steam\steamapps\common\Grand Theft Auto V\GTA5.exe', '*:\SteamLibrary\steamapps\common\Grand Theft Auto V\GTA5.exe', '*:\Program Files\Epic Games\GTAV\GTA5.exe')
          foreach ($gexe in $gx) {
            $gdir = [System.IO.Path]::GetDirectoryName($gexe)
            $mf = @(Get-ChildItem -LiteralPath $gdir -Force -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -eq '.asi' -or $_.Name -match '^(ScriptHookV|dinput8|ScriptHookVDotNet)' })
            if ($mf.Count) { Hit "gtamods:$gdir" 'GTA V' 'info' "$($mf.Count) Mod-Loader-Dateien im GTA-Ordner" ((($mf | Select-Object -First 6) | ForEach-Object { $_.Name }) -join ', ') '' }
          }
        } catch {}

        Prog 'files' 'Datei-Analyse'
        $cand = @(@($susp) + @($userRuns | Where-Object { $_ -match '\.(exe|dll|sys)$' }) | Where-Object { $_ } | Select-Object -Unique)
        $analyzed = 0
        $unsigned = New-Object System.Collections.ArrayList
        foreach ($fp in $cand) {
          if ($analyzed -ge 30) { break }
          if (-not (Test-Path -LiteralPath $fp -PathType Leaf)) { continue }
          $fi = Get-Item -LiteralPath $fp -Force -ErrorAction SilentlyContinue
          if (-not $fi) { continue }
          if ([int64]$fi.Attributes -band 0x401000) { continue }   # nur in der Cloud (OneDrive) – nicht herunterladen
          if ($fi.Length -gt 300MB) { continue }   # große Installer: Signatur und Hash würden die ganze Datei lesen
          $analyzed++
          $leaf = [System.IO.Path]::GetFileName($fp)
          $signed = $false
          try { $sig = Get-AuthenticodeSignature -LiteralPath $fp -ErrorAction Stop; if ($sig.Status -eq 'Valid') { $signed = $true } } catch {}
          if ($signed) { continue }
          [void]$unsigned.Add($leaf)
          $why = New-Object System.Collections.ArrayList
          $sev = 'info'
          $hash = ''; try { $hash = (Get-FileHash -LiteralPath $fp -Algorithm SHA256 -ErrorAction Stop).Hash } catch {}
          if ($usnOk) {
            try {
              $pp4 = ([string][KaritoUsn]::PeInfo($fp, 16777216, [string[]]@($ScanNeedles))).Split([char[]]@('|'), 4)
              $ent = [double]::Parse($pp4[0], [Globalization.CultureInfo]::InvariantCulture)
              if ($ent -ge 7.2) { [void]$why.Add("stark gepackt (Entropie $([math]::Round($ent, 2)))") }
              if ($pp4[1] -match '\.vmp|themida|winlice|enigma|mpress|UPX|aspack|obsidium') { [void]$why.Add("Schutz/Packer: $($pp4[1])") }
              if ($pp4[2] -eq '1') { [void]$why.Add('.NET-Programm') }
              if ($pp4[3]) {
                [void]$why.Add("Speicher-Funktionen: $($pp4[3])")
                foreach ($cs3 in $ScanCrit) { if ($pp4[3] -match [regex]::Escape($cs3)) { $sev = 'crit' } }
              }
            } catch {}
          }
          $lv = KwLevel $leaf
          if ($sev -ne 'crit') { if ($lv -eq 'crit') { $sev = 'crit' } elseif ($why.Count -ge 2 -or ($why.Count -ge 1 -and $lv)) { $sev = 'warn' } }
          if ($why.Count -or $lv) { Hit "file:$leaf" 'Verdächtige Dateien' $sev "$leaf ist unsigniert und auffällig" ((@($why) -join ' · ') + ' · ' + $fp) '' $hash }
        }
        if ($unsigned.Count) { Hit 'unsigned' 'Programmstarts' 'info' "$($unsigned.Count) unsignierte Programme gestartet" ((@($unsigned | Select-Object -Unique) | Select-Object -First 8) -join ', ') '' }
        Hit 'analyzed' 'Datei-Analyse' 'ok' "$analyzed Programme analysiert" 'Signatur, Packer, Entropie und typische Speicher-Funktionen' ''

        Prog 'done' 'Bericht'
        if (@($scanItems | Where-Object { $_.sev -in 'crit', 'warn' }).Count -eq 0) { Hit 'clean' 'Ergebnis' 'ok' 'Keine Auffälligkeiten gefunden' 'Der Check zeigt Hinweise, keine Beweise.' '' }
}
