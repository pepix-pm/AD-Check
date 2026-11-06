<#
.SYNOPSIS
    PEPIX AD-Check — przegląd bezpieczeństwa Active Directory (wersja 0.7)

.DESCRIPTION
    Uruchamiać ze stacji w domenie klienta (moduł RSAT ActiveDirectory).
    Domyślnie WYSTARCZY ZWYKŁE KONTO DOMENOWE:
      - dane katalogowe: zapytania LDAP,
      - Print Spooler na DC: test potoku \\DC\pipe\spoolss,
      - SMBv1 na DC: sonda negocjacji SMB1 na TCP 445,
      - podpisywanie LDAP, channel binding, poziom NTLM: odczyt GPO z SYSVOL (GptTmpl.inf).
    -UseWinRM: zamiast GPO i sond odczyt rzeczywistych wartości z rejestru DC (wymaga admina na DC).
    Wynik: szczegółowy raport HTML, JSON (do porównań), CSV znalezisk i CSV obiektów.
    Punkty: Critical=25, High=10, Medium=3, Low=1 za znalezisko; im mniej, tym lepiej.

.EXAMPLE
    .\PEPIX-ADCheck.ps1 -Klient KLIENT
    .\PEPIX-ADCheck.ps1 -Klient KLIENT -Server firma.local -UseWinRM
    .\PEPIX-ADCheck.ps1 -Klient KLIENT -Previous .\raporty\AD_KLIENT_firma.local_20260101-1200.json
    # bez kopiowania pliku na serwer (z prywatnego repo GitHub) - patrz README, sekcja "Uruchomienie z GitHuba"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Klient,
    [string]$Server = $env:USERDNSDOMAIN,
    [string]$OutDir,
    [int]$StaleDays = 90,
    [string]$Previous,
    [switch]$UseWinRM,
    [switch]$SkipDCChecks,
    [int]$MaxRows = 500
)

$ErrorActionPreference = 'Stop'
$Version = '0.7'

#region ---------- wymagania ----------
# Sprawdzane ręcznie zamiast #Requires: skrypt bywa uruchamiany jako scriptblock (z GitHuba), gdzie #Requires nie działa.
# Wszystkie braki zbierane naraz, żeby nie poprawiać ich pojedynczo.
$braki = [System.Collections.Generic.List[string]]::new()

if ([System.Environment]::OSVersion.Platform -ne 'Win32NT') {
    $braki.Add('System inny niż Windows - moduł ActiveDirectory, SYSVOL i testy DC wymagają Windows.')
}
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    $hint = 'Windows 10/11 (PowerShell jako administrator, pobiera z Windows Update): Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0  (błąd 0x800f0954 = stacja pod WSUS, patrz README)'
    try {
        if ((Get-CimInstance Win32_OperatingSystem -Verbose:$false).ProductType -ne 1) { $hint = 'serwer: Install-WindowsFeature RSAT-AD-PowerShell' }
    } catch { $hint = "serwer: Install-WindowsFeature RSAT-AD-PowerShell; $hint" }
    $braki.Add("Brak modułu ActiveDirectory (RSAT). Instalacja - $hint")
}
if (-not $Server) {
    $braki.Add('Nie ustalono domeny: stacja/konto poza domeną. Podaj -Server <domena lub DC>.')
}
if ($Previous -and -not (Test-Path -LiteralPath $Previous -PathType Leaf)) {
    $braki.Add("Nie znaleziono pliku -Previous: $Previous")
}

if ($braki.Count -eq 0) {
    Import-Module ActiveDirectory -Verbose:$false
    try { $domain = Get-ADDomain -Server $Server }
    catch {
        $braki.Add("Brak połączenia z AD ($Server): $($_.Exception.Message). Wymagany dostęp do usługi AD Web Services na DC (TCP 9389) oraz DNS domeny.")
    }
}
if ($braki.Count -gt 0) {
    throw ("Niespełnione wymagania PEPIX AD-Check:`n - " + ($braki -join "`n - "))
}

if (-not $OutDir) {
    # z pliku: obok skryptu; z GitHuba: profil użytkownika (nie bieżący katalog - w sesji admina to często System32)
    $OutDir = if ($PSScriptRoot) { Join-Path $PSScriptRoot 'raporty' } else { Join-Path $env:USERPROFILE 'PEPIX-ADCheck\raporty' }
}
# Pliki wynikowe z BOM (Excel i przeglądarki poprawnie pokazują polskie znaki); w PS 6+ 'UTF8' oznacza UTF-8 bez BOM
$encOut = if ($PSVersionTable.PSVersion.Major -ge 6) { 'utf8BOM' } else { 'UTF8' }
#endregion

$now      = Get-Date
$staleDt  = $now.AddDays(-$StaleDays)
$forest   = Get-ADForest -Server $Server
$rootDse  = Get-ADRootDSE -Server $Server
$dSid     = $domain.DomainSID.Value
$findings = [System.Collections.Generic.List[object]]::new()
$weights  = @{ Critical = 25; High = 10; Medium = 3; Low = 1; Info = 0 }

$catPriv = 'Konta uprzywilejowane'
$catUser = 'Konta użytkowników'
$catComp = 'Komputery'
$catDom  = 'Domena i las'
$catDC   = 'Kontrolery domeny'
$catHealth = 'Kondycja domeny i replikacja'
$catCis    = 'Konfiguracja DC (CIS L1)'

#region ---------- funkcje pomocnicze ----------
function Format-Date($d) { if ($d) { ([datetime]$d).ToString('yyyy-MM-dd') } else { '—' } }
function Get-ParentOU([string]$dn) { $dn -replace '^.+?(?<!\\),', '' }

# Tekst poprawki: linie łączone, znaczniki {SID} {DOMENA} {LAS} podmieniane
function Fx([string[]]$Lines) {
    ($Lines -join "`r`n").Replace('{SID}', $dSid).Replace('{DOMENA}', $domain.DNSRoot).Replace('{LAS}', $forest.Name)
}

function ConvertTo-UserRow($u) {
    if (-not $u) { return }
    [pscustomobject]@{
        Konto             = $u.SamAccountName
        Nazwa             = $u.Name
        Aktywne           = $u.Enabled
        OstatnieLogowanie = Format-Date $u.LastLogonDate
        HasloUstawione    = Format-Date $u.PasswordLastSet
        Utworzone         = Format-Date $u.whenCreated
        Kontener          = Get-ParentOU $u.DistinguishedName
    }
}

function ConvertTo-ComputerRow($c) {
    if (-not $c) { return }
    [pscustomobject]@{
        Komputer          = $c.Name
        System            = $c.OperatingSystem
        OstatnieLogowanie = Format-Date $c.LastLogonDate
        Utworzone         = Format-Date $c.whenCreated
        Kontener          = Get-ParentOU $c.DistinguishedName
    }
}

# ---------- cykl życia Windows (Microsoft Lifecycle) ----------
# AKTUALIZOWAĆ przy nowych wersjach Windows; data stanu trafia do raportu.
# Windows 11: Enterprise/Education/IoT Enterprise mają 36 mies. wsparcia wersji, Home/Pro/Pro Education 24 mies.
$osLifecycleAsOf = '2026-11'
$win11Builds = @{
    22000 = @{ Nazwa = '21H2'; Ent = '2024-10-08'; Pro = '2023-10-10' }
    22621 = @{ Nazwa = '22H2'; Ent = '2025-10-14'; Pro = '2024-10-08' }
    22631 = @{ Nazwa = '23H2'; Ent = '2026-11-10'; Pro = '2025-11-11' }
    26100 = @{ Nazwa = '24H2'; Ent = '2027-10-12'; Pro = '2026-10-13' }
    26200 = @{ Nazwa = '25H2'; Ent = '2028-10-10'; Pro = '2027-10-12' }
}
$win10Ltsc = @{
    10240 = @{ Nazwa = 'LTSB 2015'; Koniec = '2025-10-14' }
    14393 = @{ Nazwa = 'LTSB 2016'; Koniec = '2026-10-13' }
    17763 = @{ Nazwa = 'LTSC 2019'; Koniec = '2029-01-09' }
    19044 = @{ Nazwa = 'LTSC 2021'; Koniec = '2027-01-12'; IoT = '2032-01-13' }
}
$serverEol = [ordered]@{ '2025' = '2034-11-14'; '2022' = '2031-10-14'; '2019' = '2029-01-09'; '2016' = '2027-01-12'
                         '2012' = '2023-10-10'; '2008' = '2020-01-14'; '2003' = '2015-07-14' }
$legacyClient = [ordered]@{ 'Windows 8.1' = '2023-01-10'; 'Windows 8' = '2016-01-12'; 'Windows 7' = '2020-01-14'
                            'Vista' = '2017-04-11'; 'Windows XP' = '2014-04-08'; 'Windows 2000' = '2010-07-13'; 'Windows NT' = '2004-12-31' }

# Wersja i data końca wsparcia na podstawie atrybutów operatingSystem i operatingSystemVersion ("10.0 (22631)").
# Typ: Legacy | Serwer | LTSC | W10 | W11 | Inne (system spoza Windows lub nierozpoznany - bez oceny).
function Get-OsLifecycle([string]$Os, [string]$Ver) {
    $build = 0
    if ($Ver -match '\((\d+)\)') { $build = [int]$Matches[1] }
    $r = [pscustomobject]@{ Typ = 'Inne'; Wersja = ''; Koniec = $null }
    if ($Os -notmatch 'Windows') { return $r }

    foreach ($k in $legacyClient.Keys) {
        if ($Os -match [regex]::Escape($k)) { $r.Typ = 'Legacy'; $r.Wersja = $k; $r.Koniec = [datetime]$legacyClient[$k]; return $r }
    }
    if ($Os -match 'Windows Server') {
        $r.Typ = 'Serwer'
        foreach ($y in $serverEol.Keys) {
            if ($Os -match "Server $y") { $r.Wersja = $(if ($Os -match "$y R2") { "$y R2" } else { $y }); $r.Koniec = [datetime]$serverEol[$y]; return $r }
        }
        # Bez roku w nazwie i build < 20348 = kanał półroczny (SAC 1709-20H2), wszystkie bez wsparcia
        if ($build -gt 0 -and $build -lt 20348) { $r.Wersja = "SAC (build $build)"; $r.Koniec = [datetime]'2022-08-09' }
        return $r
    }
    if ($Os -match 'Windows 10') {
        if ($Os -match 'LTS[BC]' -and $win10Ltsc.ContainsKey($build)) {
            $l = $win10Ltsc[$build]
            $r.Typ = 'LTSC'; $r.Wersja = $l.Nazwa
            $r.Koniec = [datetime]$(if ($Os -match 'IoT' -and $l.IoT) { $l.IoT } else { $l.Koniec })
            return $r
        }
        $r.Typ = 'W10'; $r.Wersja = $(if ($build -eq 19045) { '22H2' } else { "build $build" }); $r.Koniec = [datetime]'2025-10-14'
        return $r
    }
    if ($Os -match 'Windows 11') {
        if ($Os -match 'LTSC') {
            $r.Typ = 'LTSC'; $r.Wersja = 'LTSC 2024'; $r.Koniec = [datetime]$(if ($Os -match 'IoT') { '2034-10-10' } else { '2029-10-09' })
            return $r
        }
        $r.Typ = 'W11'
        if ($win11Builds.ContainsKey($build)) {
            $b   = $win11Builds[$build]
            $ent = $Os -match 'Enterprise|Education' -and $Os -notmatch 'Pro Education'
            $r.Wersja = $b.Nazwa
            $r.Koniec = [datetime]$(if ($ent) { $b.Ent } else { $b.Pro })
        } else { $r.Wersja = "build $build" }   # nowsza wersja, której nie ma jeszcze w tabeli - bez oceny
        return $r
    }
    $r
}

# Wiersz komputera z wersją systemu i datą końca wsparcia; wejście: obiekt z polami C (komputer) i L (Get-OsLifecycle)
function ConvertTo-OsRow($x) {
    ConvertTo-ComputerRow $x.C |
        Add-Member -NotePropertyName Wersja -NotePropertyValue $x.L.Wersja -PassThru |
        Add-Member -NotePropertyName KoniecWsparcia -NotePropertyValue (Format-Date $x.L.Koniec) -PassThru
}

function Add-Finding([hashtable]$F) {
    $obj = @($F.Objects | Where-Object { $_ })
    $findings.Add([pscustomobject]@{
        Id             = $F.Id
        Category       = $F.Category
        Severity       = $F.Severity
        Title          = $F.Title
        Count          = $obj.Count
        Description    = [string]$F.Description
        Recommendation = [string]$F.Recommendation
        Fix            = [string]$F.Fix
        Mitre          = [string]$F.Mitre
        Objects        = $obj
    })
}

# Dodaje znalezisko tylko, gdy są obiekty
function Add-IfAny([hashtable]$F) {
    $obj = @($F.Objects | Where-Object { $_ })
    if ($obj.Count -gt 0) {
        $F.Objects = $obj
        $F.Title   = "$($F.Title) ($($obj.Count))"
        Add-Finding $F
    }
}

function Invoke-Check([string]$Name, [scriptblock]$Block) {
    try { & $Block }
    catch {
        Add-Finding @{ Id = "ERR-$Name"; Category = 'Błędy testów'; Severity = 'Info'
                       Title = "Test $($Name) nie wykonany: $($_.Exception.Message)" }
    }
}

function Get-InnerException($e) { while ($e.InnerException) { $e = $e.InnerException }; $e }

# Czy port TCP odpowiada (bez uprawnień)
function Test-TcpPort([string]$Computer, [int]$Port, [int]$TimeoutMs = 2000) {
    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $ar = $tcp.BeginConnect($Computer, $Port, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutMs)) { return $false }
        $tcp.EndConnect($ar); $true
    } catch { $false }
    finally { $tcp.Close() }
}

# Skrócona nazwa partycji (kontekstu nazewniczego) do tabel replikacji
function Get-NcName([string]$Nc) {
    switch -Regex ($Nc) {
        '^CN=Schema,'         { 'Schemat'; break }
        '^CN=Configuration,'  { 'Konfiguracja'; break }
        '^DC=DomainDnsZones,' { 'DomainDnsZones'; break }
        '^DC=ForestDnsZones,' { 'ForestDnsZones'; break }
        default               { "Domena ($Nc)" }
    }
}

# Czy na zdalnym hoście istnieje potok nazwany (zwykłe konto domenowe wystarcza)
function Test-RemotePipe([string]$Computer, [string]$Pipe, [int]$TimeoutMs = 3000) {
    $p = New-Object System.IO.Pipes.NamedPipeClientStream($Computer, $Pipe, [System.IO.Pipes.PipeDirection]::InOut)
    try { $p.Connect($TimeoutMs); 'Tak' }
    catch {
        $e = Get-InnerException $_.Exception
        if ($e -is [System.TimeoutException] -or $e -is [System.IO.FileNotFoundException]) { 'Nie' } else { '?' }
    }
    finally { $p.Dispose() }
}

# Sonda SMB1: negocjacja wyłącznie dialektem "NT LM 0.12"; odpowiedź z nagłówkiem \xFFSMB = SMB1 włączony
function Test-Smb1([string]$Computer, [int]$TimeoutMs = 3000) {
    [byte[]]$pkt = @(0x00,0x00,0x00,0x2F,
        0xFF,0x53,0x4D,0x42, 0x72, 0x00,0x00,0x00,0x00, 0x18, 0x53,0xC8, 0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00, 0xFF,0xFF, 0xFE,0xFF, 0x00,0x00, 0x00,0x00,
        0x00, 0x0C,0x00, 0x02) + [System.Text.Encoding]::ASCII.GetBytes('NT LM 0.12') + @(0x00)
    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $ar = $tcp.BeginConnect($Computer, 445, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutMs)) { $tcp.Close(); return '?' }
        $tcp.EndConnect($ar)
    } catch { $tcp.Close(); return '?' }
    try {
        $s = $tcp.GetStream()
        $s.ReadTimeout = $TimeoutMs
        $s.Write($pkt, 0, $pkt.Length)
        $buf = New-Object byte[] 128
        $n = $s.Read($buf, 0, $buf.Length)
        if ($n -ge 8 -and $buf[4] -eq 0xFF -and $buf[5] -eq 0x53 -and $buf[6] -eq 0x4D -and $buf[7] -eq 0x42) { 'Tak' } else { 'Nie' }
    } catch { 'Nie' }
    finally { $tcp.Close() }
}

# Ustawienia bezpieczeństwa DC z GPO podlinkowanych do domeny i OU Domain Controllers (odczyt z SYSVOL).
# Kolejność: najpierw domena, potem OU DC; w gPLink ostatni wpis = kolejność łącza 1, więc wygrywa późniejszy.
# Uproszczenie: pomijane łącza wyłączone i GPO z wyłączoną częścią Komputer; flaga Enforced nie jest uwzględniana.
function Get-DcGpoSettings {
    $keys = @{
        LDAPServerIntegrity       = 'MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity'
        LdapEnforceChannelBinding = 'MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding'
        LmCompatibilityLevel      = 'MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel'
    }
    $result = @{}
    foreach ($container in @($domain.DistinguishedName, $domain.DomainControllersContainer)) {
        $gpLink = (Get-ADObject -Identity $container -Properties gPLink -Server $Server).gPLink
        if (-not $gpLink) { continue }
        foreach ($m in [regex]::Matches($gpLink, '\[LDAP://([^;\]]+);(\d+)\]')) {
            if ([int]$m.Groups[2].Value -band 1) { continue }
            $gpo = Get-ADObject -Identity $m.Groups[1].Value -Properties displayName, gPCFileSysPath, flags -Server $Server
            if ($gpo.flags -band 2) { continue }
            $inf = Join-Path $gpo.gPCFileSysPath 'Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
            if (-not (Test-Path -LiteralPath $inf)) { continue }
            $content = Get-Content -LiteralPath $inf -Encoding Unicode
            foreach ($k in $keys.Keys) {
                $line = $content | Where-Object { $_ -like "$($keys[$k])=*" } | Select-Object -First 1
                if ($line) {
                    $val = (($line -split '=', 2)[1] -split ',')[-1].Trim()
                    $result[$k] = [pscustomobject]@{ Wartosc = [int]$val; Zrodlo = "GPO: $($gpo.displayName)" }
                }
            }
        }
    }
    $result
}

$mapLdap = @{ 0 = '0 (brak wymogu)'; 1 = '1 (brak wymogu)'; 2 = '2 (wymagane)' }
$mapCbt  = @{ 0 = '0 (nigdy)'; 1 = '1 (gdy obsługiwane)'; 2 = '2 (zawsze)' }
$mapLm   = @{ 0 = '0 (LM i NTLM)'; 1 = '1 (LM i NTLM, NTLMv2 gdy negocjowane)'; 2 = '2 (tylko NTLM)'
              3 = '3 (tylko NTLMv2)'; 4 = '4 (odrzuca LM)'; 5 = '5 (odrzuca LM i NTLMv1)' }
function Show-Val($v, $map) { if ($null -eq $v) { 'nieustawione' } elseif ($map.ContainsKey([int]$v)) { $map[[int]$v] } else { "$v" } }
# ---------- GPO kontrolerów domeny (dla kontroli CIS) ----------
# Registry.pol: nagłówek 'PReg' + wersja (4 B), potem wpisy [klucz;wartość;typ;rozmiar;dane] - łańcuchy UTF-16LE zakończone 0x0000.
# Wpis '**del.<nazwa>' usuwa wartość ustawioną przez GPO o niższym priorytecie; pozostałe wpisy '**' są pomijane.
function Read-RegistryPol([byte[]]$Bytes) {
    $list = [System.Collections.Generic.List[object]]::new()
    if (-not $Bytes -or $Bytes.Length -lt 8 -or [System.Text.Encoding]::ASCII.GetString($Bytes, 0, 4) -ne 'PReg') { return $list }
    $u = [System.Text.Encoding]::Unicode
    $i = 8
    while ($i + 2 -le $Bytes.Length) {
        if ($Bytes[$i] -ne 0x5B -or $Bytes[$i + 1] -ne 0) { break }   # '['
        $i += 2
        $f = @()
        for ($n = 0; $n -lt 2; $n++) {
            $s = $i
            while ($i + 1 -lt $Bytes.Length -and -not ($Bytes[$i] -eq 0 -and $Bytes[$i + 1] -eq 0)) { $i += 2 }
            $f += $u.GetString($Bytes, $s, $i - $s)
            $i += 4   # 0x0000 i ';'
        }
        $type = [BitConverter]::ToUInt32($Bytes, $i); $i += 6   # typ i ';'
        $size = [BitConverter]::ToUInt32($Bytes, $i); $i += 6   # rozmiar i ';'
        $data = $null
        switch ($type) {
            4  { if ($size -ge 4) { $data = [BitConverter]::ToUInt32($Bytes, $i) } }
            11 { if ($size -ge 8) { $data = [BitConverter]::ToUInt64($Bytes, $i) } }
            { $_ -in 1, 2, 7 } { if ($size -gt 0) { $data = $u.GetString($Bytes, $i, $size).TrimEnd([char]0) } }
        }
        $i += $size + 2   # dane i ']'
        $name = $f[1]; $deleted = $false
        if ($name.StartsWith('**del.')) { $name = $name.Substring(6); $deleted = $true }
        elseif ($name.StartsWith('**')) { continue }   # **delvals, **soft itp. - pomijane (uproszczenie)
        $entry = [pscustomobject]@{ Key = $f[0]; Name = $name; Type = $type; Data = $data; Deleted = $deleted }
        $list.Add($entry)
    }
    $list
}

function ConvertTo-Sid([string]$Id) {
    if ($Id -match '^S-\d-') { return $Id }
    try { (New-Object System.Security.Principal.NTAccount $Id).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $Id }
}

$sidNames = @{}
function Resolve-SidName([string]$Sid) {
    if (-not $sidNames.ContainsKey($Sid)) {
        $n = $Sid
        try { $n = (New-Object System.Security.Principal.SecurityIdentifier $Sid).Translate([System.Security.Principal.NTAccount]).Value } catch { $n = $Sid }
        $sidNames[$Sid] = $n
    }
    $sidNames[$Sid]
}

# Zbiorcza konfiguracja z GPO podlinkowanych do domeny i OU Domain Controllers (kolejność i uproszczenia jak w Get-DcGpoSettings).
# Registry: 'ścieżka\wartość' (małe litery, bez HKLM) -> {Wartosc, Zrodlo}; Rights: SeXxx -> {Wartosc = SID-y, Zrodlo}; Audit: GUID podkategorii -> {Wartosc 0-3, Zrodlo}
function Get-DcGpoPolicy {
    $pol = [pscustomobject]@{ Registry = @{}; Rights = @{}; Audit = @{} }
    foreach ($container in @($domain.DistinguishedName, $domain.DomainControllersContainer)) {
        $gpLink = (Get-ADObject -Identity $container -Properties gPLink -Server $Server).gPLink
        if (-not $gpLink) { continue }
        foreach ($m in [regex]::Matches($gpLink, '\[LDAP://([^;\]]+);(\d+)\]')) {
            if ([int]$m.Groups[2].Value -band 1) { continue }
            $gpo = Get-ADObject -Identity $m.Groups[1].Value -Properties displayName, gPCFileSysPath, flags -Server $Server
            if ($gpo.flags -band 2) { continue }
            $src  = "GPO: $($gpo.displayName)"
            $root = Join-Path $gpo.gPCFileSysPath 'Machine'

            $inf = Join-Path $root 'Microsoft\Windows NT\SecEdit\GptTmpl.inf'
            if (Test-Path -LiteralPath $inf) {
                $sec = ''
                foreach ($line in (Get-Content -LiteralPath $inf -Encoding Unicode)) {
                    if ($line -match '^\s*\[(.+)\]\s*$') { $sec = $Matches[1]; continue }
                    if ($line -notmatch '^\s*([^=]+?)\s*=\s*(.*)$') { continue }
                    $k = $Matches[1]; $v = $Matches[2].Trim()
                    if ($sec -eq 'Registry Values') {
                        $t, $val = $v -split ',', 2
                        $wart = if ($t -eq '4') { [int64]$val } else { "$val".Trim('"') }
                        $pol.Registry[($k -replace '^MACHINE\\', '').ToLower()] = [pscustomobject]@{ Wartosc = $wart; Zrodlo = $src }
                    } elseif ($sec -eq 'Privilege Rights') {
                        $sids = @($v -split ',' | ForEach-Object { $_.Trim().TrimStart('*') } | Where-Object { $_ } | ForEach-Object { ConvertTo-Sid $_ })
                        $pol.Rights[$k] = [pscustomobject]@{ Wartosc = $sids; Zrodlo = $src }
                    }
                }
            }
            $polFile = Join-Path $root 'Registry.pol'
            if (Test-Path -LiteralPath $polFile) {
                foreach ($e in @(Read-RegistryPol ([System.IO.File]::ReadAllBytes($polFile)))) {
                    $key = "$($e.Key)\$($e.Name)".ToLower()
                    if ($e.Deleted) { [void]$pol.Registry.Remove($key) }
                    else { $pol.Registry[$key] = [pscustomobject]@{ Wartosc = $e.Data; Zrodlo = $src } }
                }
            }
            $csv = Join-Path $root 'Microsoft\Windows NT\Audit\audit.csv'
            if (Test-Path -LiteralPath $csv) {
                foreach ($a in @(Import-Csv -LiteralPath $csv)) {
                    $g = "$($a.'Subcategory GUID')".Trim('{', '}').ToLower()
                    if ($g) { $pol.Audit[$g] = [pscustomobject]@{ Wartosc = [int]$a.'Setting Value'; Zrodlo = $src } }
                }
            }
        }
    }
    $pol
}

# Ocena wartości kontroli CIS; $null = nieustawione -> wartość domyślna systemu (D), brak domyślnej = niezgodne
function Test-CisValue($Value, [hashtable]$Control) {
    $v = $Value
    if ($null -eq $v) { $v = $Control.D }
    if ($null -eq $v) { return $false }
    try { $n = [int64]$v } catch { return $false }
    switch ($Control.Op) {
        'eq'    { return ($n -eq [int64]$Control.E) }
        'ge'    { return ($n -ge [int64]$Control.E) }
        'le-nz' { return ($n -gt 0 -and $n -le [int64]$Control.E) }
        'aes'   { return (($n -band 0x18) -ne 0 -and ($n -band 0x7) -eq 0) }   # AES128/AES256, bez DES i RC4
    }
    $false
}

# Tekst "Inclusion Setting" z auditpol /r -> 0 brak, 1 Success, 2 Failure, 3 oba (angielski i polski)
function ConvertFrom-AuditText([string]$Text) {
    $v = 0
    if ($Text -match '(?i)(^|\s)(success|sukces|powodz)') { $v = $v -bor 1 }
    if ($Text -match '(?i)(failure|niepowodz|błąd|błęd)') { $v = $v -bor 2 }
    $v
}

function Get-TopSeverity($Rows) {
    foreach ($s in 'Critical', 'High', 'Medium', 'Low') { if (@($Rows | Where-Object Waga -eq $s).Count) { return $s } }
    'Low'
}
#endregion

#region ---------- dane bazowe i inwentaryzacja ----------
$dcs = @(Get-ADDomainController -Filter * -Server $Server)
$pp  = Get-ADDefaultDomainPasswordPolicy -Server $Server
$trusts = @()
try { $trusts = @(Get-ADTrust -Filter * -Server $Server) } catch { }

$userProps = 'PasswordNeverExpires','PasswordLastSet','LastLogonDate','AccountNotDelegated',
             'ServicePrincipalName','Enabled','MemberOf','adminCount','DoesNotRequirePreAuth',
             'SIDHistory','whenCreated','userAccountControl','TrustedForDelegation'

# Grupy uprzywilejowane po SID (nazwy bywają spolszczone)
$isRoot = $domain.DNSRoot -eq $forest.RootDomain
$privGroups = [ordered]@{
    'Administrators (BUILTIN)' = 'S-1-5-32-544'
    'Domain Admins'            = "$dSid-512"
    'Account Operators'        = 'S-1-5-32-548'
    'Server Operators'         = 'S-1-5-32-549'
    'Print Operators'          = 'S-1-5-32-550'
    'Backup Operators'         = 'S-1-5-32-551'
}
if ($isRoot) {
    $privGroups['Enterprise Admins'] = "$dSid-519"
    $privGroups['Schema Admins']     = "$dSid-518"
}

$groupMembers = @{}
$privSids     = @{}
foreach ($g in $privGroups.GetEnumerator()) {
    try {
        $m = @(Get-ADGroupMember -Identity $g.Value -Recursive -Server $Server | Where-Object objectClass -eq 'user')
        $groupMembers[$g.Key] = $m
        foreach ($u in $m) { $privSids[$u.SID.Value] = $true }
    } catch {
        Add-Finding @{ Id = 'ERR-PRIV'; Category = 'Błędy testów'; Severity = 'Info'
                       Title = "Nie odczytano grupy $($g.Key): $($_.Exception.Message)" }
    }
}
$privBySid = @{}
foreach ($sid in $privSids.Keys) { $privBySid[$sid] = Get-ADUser -Identity $sid -Properties $userProps -Server $Server }
$privUsers = @($privBySid.Values)
function Get-GroupRows([string]$Name) { @($groupMembers[$Name]) | ForEach-Object { ConvertTo-UserRow $privBySid[$_.SID.Value] } }

$protectedUsersDn = $null
try { $protectedUsersDn = (Get-ADGroup -Identity "$dSid-525" -Server $Server).DistinguishedName } catch { }

$invPriv = foreach ($gName in $privGroups.Keys) {
    foreach ($m in @($groupMembers[$gName])) {
        $u = $privBySid[$m.SID.Value]
        if ($u) {
            [pscustomobject]@{
                Grupa             = $gName
                Konto             = $u.SamAccountName
                Nazwa             = $u.Name
                Aktywne           = $u.Enabled
                OstatnieLogowanie = Format-Date $u.LastLogonDate
                HasloUstawione    = Format-Date $u.PasswordLastSet
                HasloBezWygasania = $u.PasswordNeverExpires
            }
        }
    }
}
#endregion

#region ---------- konta uprzywilejowane ----------
Invoke-Check 'PRIV' {
    $da = @($groupMembers['Domain Admins'])
    if ($da.Count -gt 5) {
        Add-Finding @{
            Id = 'P-DA-COUNT'; Category = $catPriv; Severity = 'Medium'
            Title = "Domain Admins ma $($da.Count) członków (rekursywnie)"
            Objects = (Get-GroupRows 'Domain Admins')
            Description = 'Każde konto Domain Admins to pełna kontrola nad domeną. Im więcej takich kont, tym więcej haseł, sesji i stacji, z których można przejąć domenę.'
            Recommendation = 'Ograniczyć do 2–4 imiennych kont administracyjnych używanych wyłącznie do administracji AD; pozostałe zadania przez delegację uprawnień na OU.'
            Fix = (Fx 'Remove-ADGroupMember -Identity ''{SID}-512'' -Members <konto>')
            Mitre = 'T1078.002'
        }
    }
    foreach ($g in 'Schema Admins','Account Operators','Server Operators','Print Operators','Backup Operators') {
        Add-IfAny @{
            Id = "P-$($g -replace ' ','')"; Category = $catPriv; Severity = 'Medium'
            Title = "Grupa $g nie jest pusta"
            Objects = (Get-GroupRows $g)
            Description = "Członkowie grupy $g mają uprawnienia pozwalające w praktyce przejąć domenę (np. logowanie na DC, kopia NTDS.dit, modyfikacja kont lub schematu)."
            Recommendation = 'Grupa powinna być pusta. Członkostwo nadawać czasowo, na czas konkretnej zmiany (RFC), i usuwać po jej zakończeniu.'
            Fix = (Fx "Remove-ADGroupMember -Identity '$($privGroups[$g])' -Members <konto>")
            Mitre = 'T1078.002'
        }
    }

    $en = @($privUsers | Where-Object Enabled)
    Add-IfAny @{
        Id = 'P-PNE'; Category = $catPriv; Severity = 'High'
        Title = 'Konta uprzywilejowane z hasłem bez wygasania'
        Objects = ($en | Where-Object PasswordNeverExpires | ForEach-Object { ConvertTo-UserRow $_ })
        Description = 'Hasło konta uprzywilejowanego, które nigdy nie wygasa, bywa niezmieniane latami. Wyciek z dowolnego momentu w przeszłości nadal daje dostęp.'
        Recommendation = 'Wyłączyć PasswordNeverExpires i zmienić hasła. Konta serwisowe zastąpić gMSA i wyjąć z grup uprzywilejowanych.'
        Fix = (Fx 'Set-ADUser -Identity <konto> -PasswordNeverExpires $false', 'Set-ADUser -Identity <konto> -ChangePasswordAtLogon $true')
        Mitre = 'T1078.002'
    }
    Add-IfAny @{
        Id = 'P-SPN'; Category = $catPriv; Severity = 'High'
        Title = 'Konta uprzywilejowane z SPN (Kerberoasting)'
        Objects = ($en | Where-Object ServicePrincipalName | ForEach-Object {
                    ConvertTo-UserRow $_ | Add-Member -NotePropertyName SPN -NotePropertyValue ($_.ServicePrincipalName -join ', ') -PassThru })
        Description = 'Każdy użytkownik domeny może pobrać bilet TGS dla konta z SPN i łamać jego hasło offline. Dla konta uprzywilejowanego oznacza to bezpośrednią ścieżkę do przejęcia domeny.'
        Recommendation = 'Usunąć SPN z kont administracyjnych. Konta usług przenieść na gMSA i wyjąć z grup uprzywilejowanych.'
        Fix = (Fx 'Set-ADUser -Identity <konto> -ServicePrincipalNames @{Remove=''<SPN>''}')
        Mitre = 'T1558.003'
    }
    Add-IfAny @{
        Id = 'P-DELEG'; Category = $catPriv; Severity = 'Medium'
        Title = 'Konta uprzywilejowane bez ochrony przed delegacją'
        Objects = ($en | Where-Object { -not $_.AccountNotDelegated -and
                    -not ($protectedUsersDn -and $_.MemberOf -contains $protectedUsersDn) } | ForEach-Object { ConvertTo-UserRow $_ })
        Description = 'Poświadczenia administratora mogą zostać przechwycone i użyte przez serwer z delegacją Kerberos, jeśli admin się do niego uwierzytelni.'
        Recommendation = 'Zaznaczyć "Konto jest poufne i nie może być delegowane" albo dodać konto do Protected Users (po teście: blokuje NTLM, DES/RC4 i buforowanie poświadczeń).'
        Fix = (Fx 'Set-ADUser -Identity <konto> -AccountNotDelegated $true', 'Add-ADGroupMember -Identity ''{SID}-525'' -Members <konto>   # Protected Users')
        Mitre = 'T1558'
    }
    Add-IfAny @{
        Id = 'P-STALE'; Category = $catPriv; Severity = 'Medium'
        Title = "Aktywne konta uprzywilejowane nieużywane > $StaleDays dni"
        Objects = ($en | Where-Object { -not $_.LastLogonDate -or $_.LastLogonDate -lt $staleDt } | ForEach-Object { ConvertTo-UserRow $_ })
        Description = 'Nieużywane, ale aktywne konto administracyjne to cel, którego przejęcia nikt nie zauważy.'
        Recommendation = 'Potwierdzić z klientem i wyłączyć; usunąć po okresie karencji.'
        Fix = (Fx 'Disable-ADAccount -Identity <konto>')
        Mitre = 'T1078.002'
    }

    $adm = Get-ADUser -Identity "$dSid-500" -Properties PasswordLastSet, LastLogonDate, whenCreated -Server $Server
    if ($adm.PasswordLastSet -and $adm.PasswordLastSet -lt $now.AddDays(-365)) {
        Add-Finding @{
            Id = 'P-ADM500'; Category = $catPriv; Severity = 'Medium'
            Title = "Hasło wbudowanego Administratora nie zmieniane od $([int]($now - $adm.PasswordLastSet).TotalDays) dni"
            Objects = (ConvertTo-UserRow $adm)
            Description = 'Wbudowane konto Administrator (RID 500) nie podlega blokadzie po błędnych hasłach i często ma hasło znane wielu osobom z przeszłości.'
            Recommendation = 'Zmienić hasło na długie losowe, przechować w Keeper, używać tylko awaryjnie.'
            Fix = (Fx 'Set-ADAccountPassword -Identity ''{SID}-500'' -Reset')
            Mitre = 'T1078.002'
        }
    }

    $krb = Get-ADUser -Identity krbtgt -Properties PasswordLastSet, whenCreated -Server $Server
    $krbAge = [int]($now - $krb.PasswordLastSet).TotalDays
    if ($krbAge -gt 180) {
        Add-Finding @{
            Id = 'P-KRBTGT'; Category = $catPriv; Severity = $(if ($krbAge -gt 365) { 'Critical' } else { 'High' })
            Title = "Hasło krbtgt nie zmieniane od $krbAge dni"
            Objects = ([pscustomobject]@{ Konto = 'krbtgt'; HasloUstawione = Format-Date $krb.PasswordLastSet; WiekDni = $krbAge })
            Description = 'Kto zna skrót hasła krbtgt, może wystawiać dowolne bilety Kerberos (Golden Ticket). Stare hasło oznacza, że każdy wyciek NTDS.dit lub kopii DC z tego okresu nadal działa.'
            Recommendation = 'Najpierw sprawdzić zdrowie replikacji. Potem zmienić hasło krbtgt dwukrotnie, z odstępem nie krótszym niż maksymalny czas życia biletu (domyślnie 10 h) plus czas replikacji. Najlepiej skryptem Microsoft New-KrbtgtKeys.ps1, zaczynając od trybu testowego.'
            Fix = (Fx 'repadmin /replsummary', 'repadmin /showrepl * /errorsonly', '# następnie New-KrbtgtKeys.ps1 (github.com/microsoft/New-KrbtgtKeys.ps1) - najpierw tryb symulacji')
            Mitre = 'T1558.001'
        }
    }
}
#endregion

#region ---------- konta użytkowników ----------
Invoke-Check 'USERS' {
    $users = @(Get-ADUser -Filter 'Enabled -eq $true' -Properties $userProps -Server $Server)

    Add-IfAny @{
        Id = 'U-ASREP'; Category = $catUser; Severity = 'High'
        Title = 'Konta bez preautentykacji Kerberos (AS-REP roasting)'
        Objects = ($users | Where-Object DoesNotRequirePreAuth | ForEach-Object { ConvertTo-UserRow $_ })
        Description = 'Dla tych kont każdy w sieci (nawet bez konta) może pobrać materiał do łamania hasła offline.'
        Recommendation = 'Włączyć preautentykację Kerberos; jeśli wyłączenie było potrzebne dla starej aplikacji, ustawić hasło ≥ 25 znaków.'
        Fix = (Fx 'Set-ADAccountControl -Identity <konto> -DoesNotRequirePreAuth $false')
        Mitre = 'T1558.004'
    }
    Add-IfAny @{
        Id = 'U-SPN'; Category = $catUser; Severity = 'Medium'
        Title = 'Konta użytkowników z SPN (Kerberoasting)'
        Objects = ($users | Where-Object ServicePrincipalName | ForEach-Object {
                    ConvertTo-UserRow $_ | Add-Member -NotePropertyName SPN -NotePropertyValue ($_.ServicePrincipalName -join ', ') -PassThru })
        Description = 'Każdy użytkownik domeny może pobrać bilet TGS dla tych kont i łamać ich hasła offline. Konta usług mają często słabe, niezmieniane hasła.'
        Recommendation = 'Zastąpić gMSA. Jeśli to niemożliwe: hasło ≥ 25 znaków, tylko AES, regularna zmiana.'
        Fix = (Fx 'Set-ADUser -Identity <konto> -KerberosEncryptionType AES128,AES256', '# docelowo: New-ADServiceAccount -Name <gmsa> -DNSHostName <gmsa>.{DOMENA} -PrincipalsAllowedToRetrieveManagedPassword <serwer>$')
        Mitre = 'T1558.003'
    }
    Add-IfAny @{
        Id = 'U-UNCONSTR'; Category = $catUser; Severity = 'Critical'
        Title = 'Konta użytkowników z delegacją nieograniczoną'
        Objects = ($users | Where-Object TrustedForDelegation | ForEach-Object { ConvertTo-UserRow $_ })
        Description = 'Usługa działająca na takim koncie otrzymuje pełne bilety TGT użytkowników, którzy się do niej uwierzytelniają, w tym administratorów i kont komputerów DC.'
        Recommendation = 'Usunąć delegację nieograniczoną; jeśli usługa wymaga delegacji, użyć delegacji ograniczonej (KCD/RBCD).'
        Fix = (Fx 'Set-ADAccountControl -Identity <konto> -TrustedForDelegation $false')
        Mitre = 'T1558'
    }
    Add-IfAny @{
        Id = 'U-PWDNOTREQ'; Category = $catUser; Severity = 'High'
        Title = 'Konta z flagą PASSWD_NOTREQD (hasło niewymagane)'
        Objects = ($users | Where-Object { $_.userAccountControl -band 0x20 } | ForEach-Object { ConvertTo-UserRow $_ })
        Description = 'Konto może mieć puste hasło niezależnie od polityki haseł.'
        Recommendation = 'Usunąć flagę i wymusić zmianę hasła.'
        Fix = (Fx 'Set-ADAccountControl -Identity <konto> -PasswordNotRequired $false', 'Set-ADUser -Identity <konto> -ChangePasswordAtLogon $true')
        Mitre = 'T1078.002'
    }
    Add-IfAny @{
        Id = 'U-REVERSIBLE'; Category = $catUser; Severity = 'High'
        Title = 'Konta z hasłem przechowywanym odwracalnie'
        Objects = ($users | Where-Object { $_.userAccountControl -band 0x80 } | ForEach-Object { ConvertTo-UserRow $_ })
        Description = 'Hasło jest zapisane w AD w postaci możliwej do odszyfrowania; kopia NTDS.dit ujawnia je jawnym tekstem.'
        Recommendation = 'Wyłączyć szyfrowanie odwracalne, potem zmienić hasło (stara wartość pozostaje do zmiany).'
        Fix = (Fx 'Set-ADUser -Identity <konto> -AllowReversiblePasswordEncryption $false', 'Set-ADUser -Identity <konto> -ChangePasswordAtLogon $true')
        Mitre = 'T1003.003'
    }
    Add-IfAny @{
        Id = 'U-DES'; Category = $catUser; Severity = 'High'
        Title = 'Konta z wymuszonym szyfrowaniem DES'
        Objects = ($users | Where-Object { $_.userAccountControl -band 0x200000 } | ForEach-Object { ConvertTo-UserRow $_ })
        Description = 'DES jest złamany; bilety Kerberos takich kont można odszyfrować.'
        Recommendation = 'Wyłączyć USE_DES_KEY_ONLY i zmienić hasło.'
        Fix = (Fx 'Set-ADAccountControl -Identity <konto> -UseDESKeyOnly $false')
        Mitre = 'T1558'
    }
    Add-IfAny @{
        Id = 'U-SIDHIST'; Category = $catUser; Severity = 'Medium'
        Title = 'Konta z atrybutem SIDHistory'
        Objects = ($users | Where-Object { $_.SIDHistory.Count -gt 0 } | ForEach-Object {
                    ConvertTo-UserRow $_ | Add-Member -NotePropertyName SIDHistory -NotePropertyValue (($_.SIDHistory | ForEach-Object { $_.Value }) -join ', ') -PassThru })
        Description = 'SIDHistory nadaje uprawnienia SID-ów z innej domeny. Pozostałość po migracji, a zarazem znany mechanizm ukrywania uprawnień przez atakującego.'
        Recommendation = 'Po zakończonej migracji wyczyścić SIDHistory; jeśli SID należy do grupy uprzywilejowanej - traktować jak incydent.'
        Fix = (Fx 'Set-ADUser -Identity <konto> -Remove @{sIDHistory=''<SID>''}')
        Mitre = 'T1134.005'
    }
    Add-IfAny @{
        Id = 'U-PNE'; Category = $catUser; Severity = 'Low'
        Title = 'Zwykłe konta z hasłem bez wygasania'
        Objects = ($users | Where-Object { $_.PasswordNeverExpires -and -not $privSids[$_.SID.Value] } | ForEach-Object { ConvertTo-UserRow $_ })
        Description = 'Hasła takich kont bywają niezmieniane latami; wyciek z przeszłości nadal działa.'
        Recommendation = 'Ograniczyć do uzasadnionych kont technicznych (najlepiej gMSA); użytkownikom włączyć wygasanie lub MFA i długie hasła.'
        Fix = (Fx 'Set-ADUser -Identity <konto> -PasswordNeverExpires $false')
        Mitre = 'T1078.002'
    }
    Add-IfAny @{
        Id = 'U-STALE'; Category = $catUser; Severity = 'Low'
        Title = "Aktywne konta nieużywane > $StaleDays dni"
        Objects = ($users | Where-Object { (-not $_.LastLogonDate -or $_.LastLogonDate -lt $staleDt) -and $_.whenCreated -lt $staleDt } |
                   ForEach-Object { ConvertTo-UserRow $_ })
        Description = 'Konta byłych pracowników i nieużywane konta techniczne zwiększają powierzchnię ataku; ich przejęcie jest trudne do zauważenia.'
        Recommendation = 'Potwierdzić z klientem, wyłączyć i przenieść do OU nieaktywnych; usunąć po karencji (np. 90 dni).'
        Fix = (Fx 'Disable-ADAccount -Identity <konto>')
        Mitre = 'T1078.002'
    }
    Add-IfAny @{
        Id = 'U-ADMINCOUNT'; Category = $catUser; Severity = 'Low'
        Title = 'Konta z adminCount=1 spoza grup uprzywilejowanych (osierocone)'
        Objects = ($users | Where-Object { $_.adminCount -eq 1 -and -not $privSids[$_.SID.Value] } | ForEach-Object { ConvertTo-UserRow $_ })
        Description = 'Konto było kiedyś w grupie chronionej. Ma wyłączone dziedziczenie uprawnień, więc delegacje z OU go nie obejmują, a dawne uprawnienia mogły zostać.'
        Recommendation = 'Wyczyścić adminCount i włączyć dziedziczenie uprawnień na obiekcie (Właściwości > Zabezpieczenia > Zaawansowane).'
        Fix = (Fx 'Set-ADUser -Identity <konto> -Clear adminCount')
        Mitre = 'T1098'
    }

    $guest = Get-ADUser -Identity "$dSid-501" -Properties LastLogonDate, PasswordLastSet, whenCreated -Server $Server
    if ($guest.Enabled) {
        Add-Finding @{
            Id = 'U-GUEST'; Category = $catUser; Severity = 'High'; Title = 'Konto Gość jest włączone'
            Objects = (ConvertTo-UserRow $guest)
            Description = 'Konto Gość umożliwia dostęp bez imiennego uwierzytelnienia.'
            Recommendation = 'Wyłączyć konto Gość.'
            Fix = (Fx 'Disable-ADAccount -Identity ''{SID}-501''')
            Mitre = 'T1078.001'
        }
    }
}
#endregion

#region ---------- komputery i LAPS ----------
$invOs      = [System.Collections.Generic.List[object]]::new()   # wypełniana w teście COMPUTERS
$lapsSchema = @{}                                                # lDAPDisplayName -> schemaIDGUID, wypełniana w teście COMPUTERS
$lapsOUs    = [System.Collections.Generic.List[string]]::new()   # kontenery z komputerami (nie-DC) - do analizy ACL LAPS
Invoke-Check 'COMPUTERS' {
    # Atrybuty LAPS obecne w schemacie (legacy: ms-Mcs-*, Windows LAPS: msLAPS-*), z GUID-ami do analizy ACL
    Get-ADObject -SearchBase $rootDse.schemaNamingContext -Server $Server -Properties lDAPDisplayName, schemaIDGUID -LDAPFilter (
        '(|(lDAPDisplayName=ms-Mcs-AdmPwd)(lDAPDisplayName=ms-Mcs-AdmPwdExpirationTime)(lDAPDisplayName=msLAPS-Password)' +
        '(lDAPDisplayName=msLAPS-EncryptedPassword)(lDAPDisplayName=msLAPS-PasswordExpirationTime))') |
        ForEach-Object { $lapsSchema[$_.lDAPDisplayName] = [guid]::new([byte[]]$_.schemaIDGUID) }
    $lapsAttrs = @('ms-Mcs-AdmPwdExpirationTime', 'msLAPS-PasswordExpirationTime' | Where-Object { $lapsSchema.ContainsKey($_) })

    $props = @('OperatingSystem','OperatingSystemVersion','LastLogonDate','TrustedForDelegation','primaryGroupID','whenCreated') + $lapsAttrs
    $comps = @(Get-ADComputer -Filter 'Enabled -eq $true' -Properties $props -Server $Server)
    $nonDc = @($comps | Where-Object { $_.primaryGroupID -notin 516, 521 })

    Add-IfAny @{
        Id = 'C-UNCONSTR'; Category = $catComp; Severity = 'Critical'
        Title = 'Komputery (nie-DC) z delegacją nieograniczoną'
        Objects = ($nonDc | Where-Object TrustedForDelegation | ForEach-Object { ConvertTo-ComputerRow $_ })
        Description = 'Kto przejmie taki serwer, zbiera bilety TGT wszystkich, którzy się do niego uwierzytelniają. W połączeniu z wymuszeniem uwierzytelnienia DC (np. Print Spooler) daje to przejęcie domeny.'
        Recommendation = 'Usunąć delegację nieograniczoną; jeśli usługa jej wymaga, przejść na delegację ograniczoną (KCD/RBCD).'
        Fix = (Fx 'Set-ADAccountControl -Identity ''<komputer>$'' -TrustedForDelegation $false')
        Mitre = 'T1558'
    }
    $osRows = @($comps | ForEach-Object { [pscustomobject]@{ C = $_; L = (Get-OsLifecycle $_.OperatingSystem $_.OperatingSystemVersion) } })
    $soon   = $now.AddDays(365)

    $osRows | Group-Object { "$($_.C.OperatingSystem)|$($_.L.Wersja)" } | Sort-Object Count -Descending | ForEach-Object {
        $f = $_.Group[0]
        $invOs.Add([pscustomobject]@{
            System          = $(if ($f.C.OperatingSystem) { $f.C.OperatingSystem } else { '(brak danych)' })
            Wersja          = $f.L.Wersja
            Komputery       = $_.Count
            AktywneOstatnio = @($_.Group | Where-Object { $_.C.LastLogonDate -ge $staleDt }).Count
            KoniecWsparcia  = (Format-Date $f.L.Koniec)
        })
    }

    Add-IfAny @{
        Id = 'C-OS-EOL'; Category = $catComp; Severity = 'High'
        Title = 'Aktywne konta komputerów z systemem bez wsparcia'
        Objects = ($osRows | Where-Object { $_.L.Typ -in 'Legacy','Serwer','LTSC' -and $_.L.Koniec -and $_.L.Koniec -lt $now } |
                   Sort-Object { $_.L.Koniec } | ForEach-Object { ConvertTo-OsRow $_ })
        Description = 'Systemy, dla których Microsoft nie wydaje już poprawek bezpieczeństwa (Windows 7/8.1, Server 2012 R2 i starsze, wycofane wersje LTSC i kanału półrocznego). Znane podatności pozostają otwarte na stałe. Kolumna OstatnieLogowanie odróżnia komputery używane od zapomnianych kont (patrz też C-STALE).'
        Recommendation = 'Zaplanować migrację lub wymianę; do tego czasu izolacja sieciowa (osobny VLAN, tylko niezbędne porty), brak logowania kont uprzywilejowanych, ewentualnie płatne ESU, jeśli dostępne. Nieużywane konta wyłączyć.'
        Fix = (Fx '# brak poprawki skryptem - migracja systemu / wymiana sprzętu')
        Mitre = 'T1210'
    }
    Add-IfAny @{
        Id = 'C-OS-W10'; Category = $catComp; Severity = 'Medium'
        Title = 'Komputery z Windows 10 (koniec wsparcia: 14.10.2025)'
        Objects = ($osRows | Where-Object { $_.L.Typ -eq 'W10' } | ForEach-Object { ConvertTo-OsRow $_ })
        Description = 'Windows 10 (poza wersjami LTSC) nie otrzymuje poprawek bez płatnej subskrypcji Extended Security Updates (ESU) - tylko dla wersji 22H2.'
        Recommendation = 'Migracja do Windows 11 lub potwierdzona subskrypcja ESU; zweryfikować zgodność sprzętu (TPM 2.0, procesor). Komputery w wersji starszej niż 22H2 nie mogą otrzymać ESU.'
        Fix = (Fx '# brak poprawki skryptem - migracja do Windows 11 lub ESU (tylko 22H2)')
        Mitre = 'T1210'
    }
    Add-IfAny @{
        Id = 'C-OS-FEATURE'; Category = $catComp; Severity = 'Medium'
        Title = 'Komputery z Windows 11 w wersji bez wsparcia'
        Objects = ($osRows | Where-Object { $_.L.Typ -eq 'W11' -and $_.L.Koniec -and $_.L.Koniec -lt $now } | ForEach-Object { ConvertTo-OsRow $_ })
        Description = 'Każda wersja Windows 11 (np. 23H2) otrzymuje poprawki przez 24 miesiące (Home/Pro) lub 36 miesięcy (Enterprise/Education). Te komputery nie dostały aktualizacji funkcji i nie otrzymują już poprawek bezpieczeństwa.'
        Recommendation = 'Zainstalować bieżącą aktualizację funkcji (Windows Update / WSUS / Intune). Sprawdzić, czy GPO TargetReleaseVersion lub zatwierdzenia w WSUS nie blokują aktualizacji, oraz czy komputery mają miejsce na dysku.'
        Fix = (Fx 'gpresult /h gp.html   # na komputerze: Windows Update > TargetReleaseVersion', 'reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v TargetReleaseVersionInfo')
        Mitre = 'T1210'
    }
    Add-IfAny @{
        Id = 'C-OS-SOON'; Category = $catComp; Severity = 'Medium'
        Title = 'Serwery i systemy LTSC z końcem wsparcia w ciągu 12 miesięcy'
        Objects = ($osRows | Where-Object { $_.L.Typ -in 'Serwer','LTSC' -and $_.L.Koniec -and $_.L.Koniec -ge $now -and $_.L.Koniec -lt $soon } |
                   Sort-Object { $_.L.Koniec } | ForEach-Object { ConvertTo-OsRow $_ })
        Description = 'Po dacie z kolumny KoniecWsparcia systemy przestaną otrzymywać poprawki bezpieczeństwa. Migracja serwerów (zwłaszcza DC, aplikacji, SQL) wymaga planowania z wyprzedzeniem.'
        Recommendation = 'Ująć migrację w planie i budżecie; dla każdego serwera ustalić docelowy system, właściciela i termin.'
        Fix = (Fx '# brak poprawki skryptem - plan migracji (np. Windows Server 2016 -> 2022/2025)')
        Mitre = 'T1210'
    }
    Add-IfAny @{
        Id = 'C-STALE'; Category = $catComp; Severity = 'Low'
        Title = "Aktywne konta komputerów nieużywane > $StaleDays dni"
        Objects = ($nonDc | Where-Object { (-not $_.LastLogonDate -or $_.LastLogonDate -lt $staleDt) -and $_.whenCreated -lt $staleDt } |
                   ForEach-Object { ConvertTo-ComputerRow $_ })
        Description = 'Konta nieistniejących komputerów można przejąć i wykorzystać jako tożsamość w domenie.'
        Recommendation = 'Wyłączyć, przenieść do OU nieaktywnych, usunąć po karencji.'
        Fix = (Fx 'Disable-ADAccount -Identity ''<komputer>$''')
        Mitre = 'T1078.002'
    }

    foreach ($ou in @($nonDc | ForEach-Object { Get-ParentOU $_.DistinguishedName } | Sort-Object -Unique)) { $lapsOUs.Add($ou) }

    if ($lapsAttrs.Count -eq 0) {
        Add-Finding @{
            Id = 'C-LAPS-NONE'; Category = $catComp; Severity = 'High'
            Title = 'LAPS nie wdrożony (brak atrybutów LAPS w schemacie)'
            Description = 'Bez LAPS lokalne konta administratora mają zwykle to samo hasło na wielu komputerach; przejęcie jednej stacji daje dostęp do pozostałych (pass-the-hash).'
            Recommendation = 'Wdrożyć Windows LAPS (wbudowany w aktualne Windows 10/11 i Server 2019+) przez GPO.'
            Fix = (Fx 'Update-LapsADSchema', 'Set-LapsADComputerSelfPermission -Identity ''<DN OU z komputerami>''', '# następnie GPO: Computer Configuration > Administrative Templates > System > LAPS')
            Mitre = 'T1550.002'
        }
    } else {
        # Stan LAPS komputera: typ (Windows LAPS ma pierwszeństwo) i data wygaśnięcia hasła (FILETIME)
        $lapsRows = @(foreach ($c in $nonDc) {
            $win = $c.'msLAPS-PasswordExpirationTime'; $leg = $c.'ms-Mcs-AdmPwdExpirationTime'
            $exp = $null
            try { if ($win) { $exp = [datetime]::FromFileTime([int64]$win) } elseif ($leg) { $exp = [datetime]::FromFileTime([int64]$leg) } } catch { $exp = $null }
            [pscustomobject]@{ C = $c; Typ = $(if ($win) { 'Windows LAPS' } elseif ($leg) { 'LAPS (legacy)' } else { '' }); Wygasa = $exp }
        })
        $lapsRow = { ConvertTo-ComputerRow $_.C | Add-Member -NotePropertyName LAPS -NotePropertyValue $_.Typ -PassThru |
                     Add-Member -NotePropertyName HasloWygasa -NotePropertyValue (Format-Date $_.Wygasa) -PassThru }
        $covered = @($lapsRows | Where-Object Typ).Count

        Add-IfAny @{
            Id = 'C-LAPS-MISSING'; Category = $catComp; Severity = 'Medium'
            Title = 'Komputery bez hasła zarządzanego przez LAPS'
            Objects = ($lapsRows | Where-Object { -not $_.Typ } | ForEach-Object { ConvertTo-ComputerRow $_.C })
            Description = "Te komputery nie mają hasła lokalnego administratora zarządzanego przez LAPS (LAPS ma $covered z $($lapsRows.Count) aktywnych kont komputerów poza DC). Ich lokalne hasło administratora jest prawdopodobnie wspólne z innymi komputerami."
            Recommendation = 'Sprawdzić, czy OU są objęte GPO LAPS i czy komputery mają uprawnienie do zapisu hasła. Urządzenia spoza Windows (np. Linux, NAS) wyłączyć z oceny lub zarządzać ich hasłami inaczej.'
            Fix = (Fx 'Set-LapsADComputerSelfPermission -Identity ''<DN OU>''', 'gpresult /r   # na komputerze: czy GPO LAPS jest zastosowane', 'Get-WinEvent -LogName ''Microsoft-Windows-LAPS/Operational'' -MaxEvents 20   # na komputerze')
            Mitre = 'T1550.002'
        }
        Add-IfAny @{
            Id = 'C-LAPS-EXPIRED'; Category = $catComp; Severity = 'Medium'
            Title = 'Komputery z hasłem LAPS, które przestało się zmieniać'
            Objects = ($lapsRows | Where-Object { $_.Wygasa -and $_.C.LastLogonDate -and $_.C.LastLogonDate -gt $_.Wygasa.AddDays(2) } | ForEach-Object $lapsRow)
            Description = 'Hasło LAPS wygasło, a komputer od tego czasu był w sieci (logował się do domeny) i go nie zmienił. Zwykle oznacza to usunięte GPO LAPS, brak uprawnień komputera do zapisu hasła albo odinstalowanego klienta LAPS - lokalne hasło przestaje być rotowane.'
            Recommendation = 'Sprawdzić na komputerze dziennik LAPS i zastosowanie GPO; po naprawie wymusić rotację.'
            Fix = (Fx 'Get-WinEvent -LogName ''Microsoft-Windows-LAPS/Operational'' -MaxEvents 20   # na komputerze', 'Invoke-LapsPolicyProcessing   # na komputerze, Windows LAPS', 'Reset-LapsPassword   # na komputerze, Windows LAPS')
            Mitre = 'T1550.002'
        }
        Add-IfAny @{
            Id = 'C-LAPS-LEGACY'; Category = $catComp; Severity = 'Low'
            Title = 'Komputery zarządzane przestarzałym Microsoft LAPS (legacy)'
            Objects = ($lapsRows | Where-Object { $_.Typ -eq 'LAPS (legacy)' } | ForEach-Object $lapsRow)
            Description = 'Microsoft LAPS (legacy, ms-Mcs-AdmPwd) jest wycofany i nie działa na Windows 11 23H2+ ani Windows Server 2025. Przechowuje hasło w AD bez szyfrowania, bez historii haseł i bez ochrony hasła DSRM kontrolerów domeny.'
            Recommendation = 'Migracja na Windows LAPS: rozszerzenie schematu, GPO Windows LAPS z szyfrowaniem hasła (dostęp tylko dla wskazanej grupy), po przejściu odinstalowanie klienta legacy.'
            Fix = (Fx 'Update-LapsADSchema', 'Set-LapsADComputerSelfPermission -Identity ''<DN OU>''', '# GPO: Administrative Templates > System > LAPS > Configure password backup directory = Active Directory; Enable password encryption = Enabled')
            Mitre = 'T1550.002'
        }
    }

    $maq = (Get-ADObject -Identity $domain.DistinguishedName -Properties 'ms-DS-MachineAccountQuota' -Server $Server).'ms-DS-MachineAccountQuota'
    if ($maq -gt 0) {
        Add-Finding @{
            Id = 'C-MAQ'; Category = $catComp; Severity = 'Medium'
            Title = "Każdy użytkownik może dodać do domeny $maq komputerów (MachineAccountQuota)"
            Description = 'Dowolny użytkownik może utworzyć konto komputera; to element wielu ataków eskalacji (np. RBCD, nadużycia ADCS).'
            Recommendation = 'Ustawić ms-DS-MachineAccountQuota = 0; dołączanie do domeny przez delegację uprawnień na wybranej OU.'
            Fix = (Fx 'Set-ADDomain -Identity {DOMENA} -Replace @{''ms-DS-MachineAccountQuota''=0}')
            Mitre = 'T1136.002'
        }
    }
}
#endregion

#region ---------- LAPS: dostęp do haseł ----------
# Kto może odczytać hasła LAPS: ACL kontenerów z komputerami (odczyt DACL wystarcza zwykłemu kontu).
# Hasło czyta ten, kto ma na komputerach prawo rozszerzone (CONTROL_ACCESS) do atrybutu hasła, wszystkie prawa rozszerzone albo pełną kontrolę.
Invoke-Check 'LAPS-ACL' {
    $secret = @('ms-Mcs-AdmPwd', 'msLAPS-Password', 'msLAPS-EncryptedPassword' | Where-Object { $lapsSchema.ContainsKey($_) })
    if ($secret.Count -eq 0) { return }
    $guidName = @{}; foreach ($a in $secret) { $guidName[$lapsSchema[$a]] = $a }
    $computerClass = [guid]'bf967a86-0de6-11d0-a285-00aa003049e2'
    $okSids = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-10', 'S-1-5-9', 'S-1-3-0', "$dSid-512", "$dSid-519")   # SYSTEM, Administrators, SELF, DC, CREATOR OWNER, DA, EA
    $broad  = @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', "$dSid-513", "$dSid-515")                         # Everyone, Authenticated Users, Users, Domain Users, Domain Computers
    $genericAll = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll

    $aces = foreach ($ou in $lapsOUs) {
        $sd = (Get-ADObject -Identity $ou -Properties nTSecurityDescriptor -Server $Server).nTSecurityDescriptor
        foreach ($ace in $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            if ("$($ace.AccessControlType)" -ne 'Allow' -or "$($ace.InheritanceType)" -eq 'None') { continue }
            $sid = $ace.IdentityReference.Value
            if ($sid -in $okSids) { continue }
            if ($ace.InheritedObjectType -ne [guid]::Empty -and $ace.InheritedObjectType -ne $computerClass) { continue }
            $r = $ace.ActiveDirectoryRights
            $what = $null
            if (($r -band $genericAll) -eq $genericAll) { $what = 'pełna kontrola (GenericAll)' }
            elseif ($r -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) {
                if ($ace.ObjectType -eq [guid]::Empty)          { $what = 'wszystkie prawa rozszerzone' }
                elseif ($guidName.ContainsKey($ace.ObjectType)) { $what = "odczyt $($guidName[$ace.ObjectType])" }
            }
            if ($what) { [pscustomobject]@{ Sid = $sid; Uprawnienie = $what; Kontener = $ou } }
        }
    }
    $rows = @($aces | Group-Object Sid, Uprawnienie | ForEach-Object {
        $f = $_.Group[0]
        $name = $f.Sid
        try { $name = (New-Object System.Security.Principal.SecurityIdentifier $f.Sid).Translate([System.Security.Principal.NTAccount]).Value } catch { $name = $f.Sid }
        [pscustomobject]@{ Podmiot = $name; Uprawnienie = $f.Uprawnienie; LiczbaKontenerow = @($_.Group | ForEach-Object { $_.Kontener } | Sort-Object -Unique).Count
                           Przyklad = $f.Kontener; SID = $f.Sid }
    })

    Add-IfAny @{
        Id = 'C-LAPS-READ-BROAD'; Category = $catComp; Severity = 'Critical'
        Title = 'Hasła LAPS dostępne dla szerokich grup (np. Domain Users)'
        Objects = ($rows | Where-Object { $_.SID -in $broad })
        Description = 'Każdy użytkownik domeny (lub każdy komputer) może odczytać hasło lokalnego administratora komputerów z wymienionych kontenerów. LAPS w tej postaci nie chroni, tylko ułatwia przejęcie stacji i serwerów.'
        Recommendation = 'Natychmiast usunąć uprawnienie; dostęp do haseł LAPS tylko dla dedykowanej grupy administratorów stacji/serwerów. Po zmianie wymusić rotację haseł.'
        Fix = (Fx 'Find-LapsADExtendedRights -Identity ''<DN OU>''   # Windows LAPS: kto ma dostęp', 'Find-AdmPwdExtendedRights -Identity ''<OU>''   # LAPS legacy', 'dsacls "<DN kontenera>" /R "<grupa>"   # usuwa WSZYSTKIE ACE tej grupy - najpierw zweryfikować')
        Mitre = 'T1555'
    }
    Add-IfAny @{
        Id = 'C-LAPS-READERS'; Category = $catComp; Severity = 'Low'
        Title = 'Podmioty z dostępem do haseł LAPS (do weryfikacji)'
        Objects = ($rows | Where-Object { $_.SID -notin $broad })
        Description = 'Grupy i konta spoza Domain/Enterprise Admins, które mogą odczytać hasła LAPS komputerów (bezpośrednio albo przez pełną kontrolę lub wszystkie prawa rozszerzone). Każde takie konto to ścieżka do lokalnego administratora na komputerach.'
        Recommendation = 'Zweryfikować z klientem każdy wpis. Dostęp zostawić tylko dedykowanym grupom (np. helpdesk do stacji, osobna grupa do serwerów); usunąć konta imienne, konta serwisowe i pełną kontrolę nadaną "na wszelki wypadek".'
        Fix = (Fx 'Find-LapsADExtendedRights -Identity ''<DN OU>''', 'dsacls "<DN kontenera>"   # pełna lista uprawnień')
        Mitre = 'T1555'
    }

    # Weryfikacja wprost: czy konto, którym wykonano przegląd, widzi hasła. Filtr LDAP na atrybucie poufnym
    # zwraca tylko obiekty, których atrybut konto może odczytać - wartości haseł nie są pobierane.
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $clear = @('ms-Mcs-AdmPwd', 'msLAPS-Password' | Where-Object { $lapsSchema.ContainsKey($_) })
    if ($clear.Count -and $me.User.AccountDomainSid -and $me.User.AccountDomainSid.Value -eq $dSid -and -not $privSids[$me.User.Value]) {
        $flt = '(|' + (($clear | ForEach-Object { "($_=*)" }) -join '') + ')'
        Add-IfAny @{
            Id = 'C-LAPS-READABLE'; Category = $catComp; Severity = 'High'
            Title = "Konto użyte do przeglądu ($($me.Name)) odczytuje hasła LAPS"
            Objects = (Get-ADComputer -LDAPFilter $flt -Properties OperatingSystem, LastLogonDate, whenCreated -Server $Server | ForEach-Object { ConvertTo-ComputerRow $_ })
            Description = 'Konto spoza grup uprzywilejowanych, którym uruchomiono przegląd, ma dostęp do jawnych haseł lokalnego administratora tych komputerów. Wartości haseł nie zostały pobrane ani zapisane w raporcie.'
            Recommendation = 'Ustalić, skąd pochodzi dostęp (patrz C-LAPS-READERS / C-LAPS-READ-BROAD) i czy jest uzasadniony dla tego konta.'
            Fix = (Fx 'Find-LapsADExtendedRights -Identity ''<DN OU>''')
            Mitre = 'T1555'
        }
    }
}
#endregion

#region ---------- domena i las ----------
Invoke-Check 'DOMAIN' {
    if ("$($domain.DomainMode)" -notmatch '2016|2025') {
        Add-Finding @{
            Id = 'D-DFL'; Category = $catDom; Severity = 'Low'
            Title = "Poziom funkcjonalny domeny: $($domain.DomainMode)"
            Description = 'Niższy poziom funkcjonalny blokuje część mechanizmów ochrony (m.in. pełne działanie Protected Users, nowsze opcje Kerberos).'
            Recommendation = 'Po wycofaniu starszych DC podnieść poziom funkcjonalny domeny i lasu do Windows2016.'
            Fix = (Fx 'Set-ADDomainMode -Identity {DOMENA} -DomainMode Windows2016Domain', 'Set-ADForestMode -Identity {LAS} -ForestMode Windows2016Forest')
        }
    }
    $rb = Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'" -Server $Server
    if (-not $rb.EnabledScopes) {
        Add-Finding @{
            Id = 'D-RECYCLE'; Category = $catDom; Severity = 'Medium'; Title = 'Kosz AD nie jest włączony'
            Description = 'Usunięty obiekt (konto, grupa, OU) można odtworzyć tylko z kopii zapasowej DC.'
            Recommendation = 'Włączyć Kosz AD (operacja nieodwracalna, ale bezpieczna).'
            Fix = (Fx 'Enable-ADOptionalFeature -Identity ''Recycle Bin Feature'' -Scope ForestOrConfigurationSet -Target {LAS}')
        }
    }
    if ($pp.MinPasswordLength -lt 12) {
        Add-Finding @{
            Id = 'D-PWDLEN'; Category = $catDom; Severity = 'Medium'
            Title = "Minimalna długość hasła: $($pp.MinPasswordLength)"
            Description = 'Krótkie hasła są podatne na łamanie offline i zgadywanie.'
            Recommendation = 'Min. 12 znaków dla użytkowników; 14+ dla kont uprzywilejowanych przez FGPP.'
            Fix = (Fx 'Set-ADDefaultDomainPasswordPolicy -Identity {DOMENA} -MinPasswordLength 12')
            Mitre = 'T1110'
        }
    }
    if (-not $pp.ComplexityEnabled) {
        Add-Finding @{
            Id = 'D-PWDCPLX'; Category = $catDom; Severity = 'Medium'; Title = 'Wymóg złożoności haseł wyłączony'
            Description = 'Użytkownicy mogą ustawiać hasła słownikowe.'
            Recommendation = 'Włączyć złożoność albo wdrożyć filtr haseł słownikowych/wyciekłych.'
            Fix = (Fx 'Set-ADDefaultDomainPasswordPolicy -Identity {DOMENA} -ComplexityEnabled $true')
            Mitre = 'T1110'
        }
    }
    if ($pp.LockoutThreshold -eq 0) {
        Add-Finding @{
            Id = 'D-LOCKOUT'; Category = $catDom; Severity = 'Medium'; Title = 'Brak blokady konta po błędnych hasłach'
            Description = 'Hasła można zgadywać bez ograniczeń (password spraying).'
            Recommendation = 'Ustawić próg np. 10 prób, okno i czas blokady 15 min.'
            Fix = (Fx 'Set-ADDefaultDomainPasswordPolicy -Identity {DOMENA} -LockoutThreshold 10 -LockoutObservationWindow 00:15:00 -LockoutDuration 00:15:00')
            Mitre = 'T1110.003'
        }
    }
    if ($trusts.Count) {
        Add-IfAny @{
            Id = 'D-TRUST-SIDF'; Category = $catDom; Severity = 'Medium'
            Title = 'Zewnętrzne relacje zaufania bez filtrowania SID'
            Objects = ($trusts | Where-Object { -not $_.IntraForest -and -not $_.ForestTransitive -and -not $_.SIDFilteringQuarantined -and $_.Direction -ne 'Inbound' } |
                       ForEach-Object { [pscustomobject]@{ Cel = $_.Target; Kierunek = "$($_.Direction)"; Typ = "$($_.TrustType)" } })
            Description = 'Administrator zaufanej domeny może wstrzyknąć SID-y uprzywilejowanych grup tej domeny.'
            Recommendation = 'Włączyć SID filtering (kwarantannę) na relacjach zewnętrznych.'
            Fix = (Fx 'netdom trust {DOMENA} /domain:<domena_zaufana> /quarantine:yes')
            Mitre = 'T1134.005'
        }
    }
}
#endregion

#region ---------- kontrolery domeny ----------
Invoke-Check 'DC-OS' {
    Add-IfAny @{
        Id = 'DC-OS-EOL'; Category = $catDC; Severity = 'High'
        Title = 'Kontrolery domeny z systemem bez wsparcia'
        Objects = ($dcs | ForEach-Object { $l = Get-OsLifecycle $_.OperatingSystem $_.OperatingSystemVersion
                       if ($l.Koniec -and $l.Koniec -lt $now) {
                           [pscustomobject]@{ DC = $_.HostName; System = $_.OperatingSystem; KoniecWsparcia = Format-Date $l.Koniec; Lokacja = $_.Site } } })
        Description = 'Kontroler domeny bez poprawek to najcenniejszy cel w sieci.'
        Recommendation = 'Promować nowy DC (Windows Server 2022/2025), przenieść role FSMO, zdegradować stary.'
        Fix = (Fx 'Install-ADDSDomainController -DomainName {DOMENA}   # na nowym serwerze', 'Move-ADDirectoryServerOperationMasterRole -Identity <nowy_DC> -OperationMasterRole 0,1,2,3,4')
        Mitre = 'T1210'
    }
}

$dcMethod = 'pominięte'
if (-not $SkipDCChecks) {
    $dcMethod = if ($UseWinRM) { 'rejestr DC przez WinRM (konto admina)' } else { 'sondy sieciowe + GPO z SYSVOL (zwykłe konto)' }
    $gpoSettings = @{}
    # Uzupełniamy istniejącą tabelę zamiast $script: - działa także przy uruchomieniu jako scriptblock
    if (-not $UseWinRM) { Invoke-Check 'DC-GPO' { $g = Get-DcGpoSettings; foreach ($k in $g.Keys) { $gpoSettings[$k] = $g[$k] } } }

    $dcSpool = [System.Collections.Generic.List[object]]::new()
    $dcSmb1  = [System.Collections.Generic.List[object]]::new()
    $dcLdap  = [System.Collections.Generic.List[object]]::new()
    $dcCbt   = [System.Collections.Generic.List[object]]::new()
    $dcNtlm  = [System.Collections.Generic.List[object]]::new()
    $dcUnk   = [System.Collections.Generic.List[object]]::new()

    foreach ($dc in $dcs) {
        Invoke-Check "DC-$($dc.Name)" {
            $h = $dc.HostName
            if ($UseWinRM) {
                $r = Invoke-Command -ComputerName $h -ErrorAction Stop -ScriptBlock {
                    $ntds = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ErrorAction SilentlyContinue
                    $lsa  = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
                    [pscustomobject]@{
                        Spooler = if ("$((Get-Service Spooler -ErrorAction SilentlyContinue).Status)" -eq 'Running') { 'Tak' } else { 'Nie' }
                        SMB1    = if ((Get-SmbServerConfiguration).EnableSMB1Protocol) { 'Tak' } else { 'Nie' }
                        Ldap    = $ntds.LDAPServerIntegrity
                        Cbt     = $ntds.LdapEnforceChannelBinding
                        Lm      = $lsa.LmCompatibilityLevel
                    }
                }
                $st = [pscustomobject]@{
                    Spooler = $r.Spooler; SpoolerSrc = 'usługa (WinRM)'; SMB1 = $r.SMB1; SMB1Src = 'Get-SmbServerConfiguration (WinRM)'
                    Ldap = $r.Ldap; LdapSrc = 'rejestr DC (WinRM)'; Cbt = $r.Cbt; CbtSrc = 'rejestr DC (WinRM)'; Lm = $r.Lm; LmSrc = 'rejestr DC (WinRM)'
                }
            } else {
                $smb = Test-Smb1 -Computer $h
                $spl = if ($smb -eq '?') { '?' } else { Test-RemotePipe -Computer $h -Pipe 'spoolss' }
                $gL = $gpoSettings['LDAPServerIntegrity']; $gC = $gpoSettings['LdapEnforceChannelBinding']; $gN = $gpoSettings['LmCompatibilityLevel']
                $noGpo = 'brak w GPO (wartość domyślna systemu)'
                $st = [pscustomobject]@{
                    Spooler = $spl; SpoolerSrc = 'test potoku \\DC\pipe\spoolss'
                    SMB1 = $smb; SMB1Src = 'sonda negocjacji SMB1 (TCP 445)'
                    Ldap = $gL.Wartosc; LdapSrc = $(if ($gL) { $gL.Zrodlo } else { $noGpo })
                    Cbt  = $gC.Wartosc; CbtSrc  = $(if ($gC) { $gC.Zrodlo } else { $noGpo })
                    Lm   = $gN.Wartosc; LmSrc   = $(if ($gN) { $gN.Zrodlo } else { $noGpo })
                }
            }

            switch ($st.Spooler) {
                'Tak' { $dcSpool.Add([pscustomobject]@{ DC = $h; Wynik = 'Print Spooler działa'; Metoda = $st.SpoolerSrc }) }
                '?'   { $dcUnk.Add([pscustomobject]@{ DC = $h; Test = 'Print Spooler'; Metoda = $st.SpoolerSrc }) }
            }
            switch ($st.SMB1) {
                'Tak' { $dcSmb1.Add([pscustomobject]@{ DC = $h; Wynik = 'SMBv1 przyjmuje połączenia'; Metoda = $st.SMB1Src }) }
                '?'   { $dcUnk.Add([pscustomobject]@{ DC = $h; Test = 'SMBv1 (brak połączenia z TCP 445)'; Metoda = $st.SMB1Src }) }
            }
            if ($st.Ldap -ne 2) { $dcLdap.Add([pscustomobject]@{ DC = $h; Wartosc = (Show-Val $st.Ldap $mapLdap); Zrodlo = $st.LdapSrc }) }
            if ($st.Cbt  -ne 2) { $dcCbt.Add([pscustomobject]@{ DC = $h; Wartosc = (Show-Val $st.Cbt $mapCbt); Zrodlo = $st.CbtSrc }) }
            # Windows Server 2025 nie obsługuje już NTLMv1 - pomijamy
            if ($dc.OperatingSystem -notmatch '2025' -and ($null -eq $st.Lm -or $st.Lm -lt 5)) {
                $dcNtlm.Add([pscustomobject]@{ DC = $h; Wartosc = (Show-Val $st.Lm $mapLm); Zrodlo = $st.LmSrc })
            }
        }
    }

    Add-IfAny @{
        Id = 'DC-SPOOLER'; Category = $catDC; Severity = 'High'; Title = 'Usługa Print Spooler działa na DC'; Objects = $dcSpool
        Description = 'Przez Print Spooler każdy użytkownik domeny może zmusić DC do uwierzytelnienia się do wskazanego hosta (PrinterBug). W połączeniu z delegacją nieograniczoną lub relayem NTLM prowadzi to do przejęcia domeny; usługa miała też krytyczne podatności (PrintNightmare).'
        Recommendation = 'Wyłączyć Spooler na wszystkich DC (GPO: Usługi systemowe). Jeśli DC pełni rolę serwera wydruku - najpierw przenieść kolejki na osobny serwer.'
        Fix = (Fx 'Stop-Service -Name Spooler -Force', 'Set-Service -Name Spooler -StartupType Disabled')
        Mitre = 'T1187'
    }
    Add-IfAny @{
        Id = 'DC-SMB1'; Category = $catDC; Severity = 'High'; Title = 'SMBv1 włączony na DC'; Objects = $dcSmb1
        Description = 'SMBv1 to przestarzały protokół z krytycznymi podatnościami (m.in. EternalBlue/WannaCry).'
        Recommendation = 'Sprawdzić, czy żaden klient nie korzysta z SMBv1 (Set-SmbServerConfiguration -AuditSmb1Access $true, zdarzenia 3000 w Microsoft-Windows-SMBServer/Audit), potem wyłączyć.'
        Fix = (Fx 'Set-SmbServerConfiguration -AuditSmb1Access $true -Force   # najpierw audyt', 'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force', 'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol')
        Mitre = 'T1210'
    }
    Add-IfAny @{
        Id = 'DC-LDAPSIGN'; Category = $catDC; Severity = 'Medium'; Title = 'Podpisywanie LDAP nie jest wymagane'; Objects = $dcLdap
        Description = 'Bez wymogu podpisywania możliwy jest relay NTLM do LDAP, np. dodanie konta do grupy lub ustawienie RBCD w imieniu ofiary.'
        Recommendation = 'Najpierw włączyć logowanie zdarzeń 2889 (niepodpisane powiązania) i poprawić klientów, potem w GPO Default Domain Controllers Policy ustawić "Kontroler domeny: wymagania podpisywania serwera LDAP" = Wymagaj podpisywania.'
        Fix = (Fx 'reg add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2 /f   # na DC: logowanie 2889', '# po weryfikacji klientów: GPO > Security Options > Domain controller: LDAP server signing requirements = Require signing')
        Mitre = 'T1557'
    }
    Add-IfAny @{
        Id = 'DC-LDAPCBT'; Category = $catDC; Severity = 'Medium'; Title = 'LDAP channel binding nie jest wymuszony'; Objects = $dcCbt
        Description = 'Bez channel binding możliwy jest relay NTLM do LDAPS (LDAP po TLS), który podpisywanie LDAP nie obejmuje.'
        Recommendation = 'Ustawić "Kontroler domeny: wymagania tokenu powiązania kanału serwera LDAP" najpierw na "Gdy obsługiwane" (1) i obserwować zdarzenia 3039, potem "Zawsze" (2).'
        Fix = (Fx '# GPO > Security Options > Domain controller: LDAP server channel binding token requirements = When supported, potem Always')
        Mitre = 'T1557'
    }
    Add-IfAny @{
        Id = 'DC-NTLMV1'; Category = $catDC; Severity = 'Medium'; Title = 'DC akceptuje NTLMv1/LM (LmCompatibilityLevel < 5)'; Objects = $dcNtlm
        Description = 'Odpowiedzi NTLMv1 można złamać do skrótu NT konta (w tym konta komputera DC), co daje pass-the-hash.'
        Recommendation = 'Najpierw audyt: zdarzenia 4624 na DC z "Package Name (NTLM only): NTLM V1". Po usunięciu klientów NTLMv1 ustawić w GPO poziom uwierzytelniania LAN Manager = "Wysyłaj tylko odpowiedź NTLMv2. Odmawiaj LM i NTLM".'
        Fix = (Fx 'Get-WinEvent -FilterHashtable @{LogName=''Security'';Id=4624} -MaxEvents 5000 | Where-Object { $_.Message -match ''NTLM V1'' }   # na DC', '# GPO > Security Options > Network security: LAN Manager authentication level = Send NTLMv2 response only. Refuse LM & NTLM')
        Mitre = 'T1557.001'
    }
    Add-IfAny @{
        Id = 'DC-UNKNOWN'; Category = 'Błędy testów'; Severity = 'Info'; Title = 'Testy DC nierozstrzygnięte'; Objects = $dcUnk
        Description = 'Nie udało się ustalić wyniku (brak łączności, zapora lub brak dostępu). Powtórzyć z innej stacji lub z przełącznikiem -UseWinRM.'
    }
}
#endregion

#region ---------- konfiguracja DC wg CIS (profil L1, kontroler domeny) ----------
# Wybrane kontrole CIS Microsoft Windows Server Benchmark L1 (DC), których nie obejmują inne testy (LDAP signing, NTLM, SMBv1, Spooler są w DC-*).
# Zwykłe konto: konfiguracja zamierzona z GPO (GptTmpl.inf, Registry.pol, audit.csv). -UseWinRM: rzeczywisty rejestr i auditpol każdego DC.
# Przypisanie praw użytkowników zawsze z GPO (odczyt rzeczywisty wymagałby secedit /export, czyli zapisu pliku na DC).
if (-not $SkipDCChecks) {
    $lsa = 'System\CurrentControlSet\Control\Lsa'; $msv = "$lsa\MSV1_0"; $nl = 'System\CurrentControlSet\Services\Netlogon\Parameters'
    $polSys = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'; $ts = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
    $winrm = 'Software\Policies\Microsoft\Windows\WinRM'; $evl = 'Software\Policies\Microsoft\Windows\EventLog'
    # A: SO = opcje zabezpieczeń, AT = szablony administracyjne; Op: eq / ge / le-nz / aes; D = wartość domyślna, gdy nieustawione ($null = niezgodne)
    $cisReg = @(
        @{ A = 'SO'; N = 'Accounts: Limit local account use of blank passwords to console logon only'; P = $lsa; V = 'LimitBlankPasswordUse'; Op = 'eq'; E = 1; D = 1; Ex = 'Enabled (1)'; S = 'Medium' }
        @{ A = 'SO'; N = 'Network security: Do not store LAN Manager hash value on next password change'; P = $lsa; V = 'NoLMHash'; Op = 'eq'; E = 1; D = 1; Ex = 'Enabled (1)'; S = 'High' }
        @{ A = 'SO'; N = 'Network access: Do not allow anonymous enumeration of SAM accounts'; P = $lsa; V = 'RestrictAnonymousSAM'; Op = 'eq'; E = 1; D = 1; Ex = 'Enabled (1)'; S = 'High' }
        @{ A = 'SO'; N = 'Network access: Do not allow anonymous enumeration of SAM accounts and shares'; P = $lsa; V = 'RestrictAnonymous'; Op = 'eq'; E = 1; D = 0; Ex = 'Enabled (1)'; S = 'Medium' }
        @{ A = 'SO'; N = 'Network access: Let Everyone permissions apply to anonymous users'; P = $lsa; V = 'EveryoneIncludesAnonymous'; Op = 'eq'; E = 0; D = 0; Ex = 'Disabled (0)'; S = 'High' }
        @{ A = 'SO'; N = 'Network access: Do not allow storage of passwords and credentials for network authentication'; P = $lsa; V = 'DisableDomainCreds'; Op = 'eq'; E = 1; D = 0; Ex = 'Enabled (1)'; S = 'Low' }
        @{ A = 'SO'; N = 'Audit: Force audit policy subcategory settings to override audit policy category settings'; P = $lsa; V = 'SCENoApplyLegacyAuditPolicy'; Op = 'eq'; E = 1; D = 1; Ex = 'Enabled (1)'; S = 'Low' }
        @{ A = 'SO'; N = 'Network access: Restrict anonymous access to Named Pipes and Shares'; P = 'System\CurrentControlSet\Services\LanManServer\Parameters'; V = 'RestrictNullSessAccess'; Op = 'eq'; E = 1; D = 1; Ex = 'Enabled (1)'; S = 'Medium' }
        @{ A = 'SO'; N = 'Microsoft network server: Digitally sign communications (always)'; P = 'System\CurrentControlSet\Services\LanManServer\Parameters'; V = 'RequireSecuritySignature'; Op = 'eq'; E = 1; D = $null; Ex = 'Enabled (1)'; S = 'Medium' }
        @{ A = 'SO'; N = 'Microsoft network client: Digitally sign communications (always)'; P = 'System\CurrentControlSet\Services\LanmanWorkstation\Parameters'; V = 'RequireSecuritySignature'; Op = 'eq'; E = 1; D = $null; Ex = 'Enabled (1)'; S = 'Medium' }
        @{ A = 'SO'; N = 'Network security: Minimum session security for NTLM SSP based clients'; P = $msv; V = 'NTLMMinClientSec'; Op = 'eq'; E = 537395200; D = $null; Ex = 'NTLMv2 + 128-bit (537395200)'; S = 'Low' }
        @{ A = 'SO'; N = 'Network security: Minimum session security for NTLM SSP based servers'; P = $msv; V = 'NTLMMinServerSec'; Op = 'eq'; E = 537395200; D = $null; Ex = 'NTLMv2 + 128-bit (537395200)'; S = 'Low' }
        @{ A = 'SO'; N = 'Network security: Allow LocalSystem NULL session fallback'; P = $msv; V = 'allownullsessionfallback'; Op = 'eq'; E = 0; D = 0; Ex = 'Disabled (0)'; S = 'Medium' }
        @{ A = 'SO'; N = 'Network security: Restrict NTLM: Audit Incoming NTLM Traffic'; P = $msv; V = 'AuditReceivingNTLMTraffic'; Op = 'eq'; E = 2; D = $null; Ex = 'Enable auditing for all accounts (2)'; S = 'Low' }
        @{ A = 'SO'; N = 'Network security: Restrict NTLM: Audit NTLM authentication in this domain'; P = $nl; V = 'AuditNTLMInDomain'; Op = 'eq'; E = 7; D = $null; Ex = 'Enable all (7)'; S = 'Low' }
        @{ A = 'SO'; N = 'Network security: LDAP client signing requirements'; P = 'System\CurrentControlSet\Services\LDAP'; V = 'LDAPClientIntegrity'; Op = 'ge'; E = 1; D = 1; Ex = 'Negotiate signing (1) lub wyżej'; S = 'Medium' }
        @{ A = 'SO'; N = 'Network security: Configure encryption types allowed for Kerberos'; P = "$polSys\Kerberos\Parameters"; V = 'SupportedEncryptionTypes'; Op = 'aes'; E = 2147483640; D = $null; Ex = 'AES128 + AES256 (+ Future), bez DES i RC4'; S = 'Medium' }
        @{ A = 'SO'; N = 'Domain member: Digitally encrypt or sign secure channel data (always)'; P = $nl; V = 'RequireSignOrSeal'; Op = 'eq'; E = 1; D = 1; Ex = 'Enabled (1)'; S = 'High' }
        @{ A = 'SO'; N = 'Domain member: Require strong (Windows 2000 or later) session key'; P = $nl; V = 'RequireStrongKey'; Op = 'eq'; E = 1; D = 1; Ex = 'Enabled (1)'; S = 'Medium' }
        @{ A = 'SO'; N = 'Domain controller: Refuse machine account password changes'; P = $nl; V = 'RefusePasswordChange'; Op = 'eq'; E = 0; D = 0; Ex = 'Disabled (0)'; S = 'Medium' }
        @{ A = 'SO'; N = 'Interactive logon: Machine inactivity limit'; P = $polSys; V = 'InactivityTimeoutSecs'; Op = 'le-nz'; E = 900; D = $null; Ex = '1-900 s'; S = 'Low' }
        @{ A = 'SO'; N = 'User Account Control: Admin Approval Mode for the Built-in Administrator account'; P = $polSys; V = 'FilterAdministratorToken'; Op = 'eq'; E = 1; D = 0; Ex = 'Enabled (1)'; S = 'Low' }
        @{ A = 'SO'; N = 'User Account Control: Run all administrators in Admin Approval Mode'; P = $polSys; V = 'EnableLUA'; Op = 'eq'; E = 1; D = 1; Ex = 'Enabled (1)'; S = 'Medium' }
        @{ A = 'AT'; N = 'WDigest Authentication (hasła jawnym tekstem w pamięci LSASS)'; P = "$($lsa -replace 'Lsa$','SecurityProviders\WDigest')"; V = 'UseLogonCredential'; Op = 'eq'; E = 0; D = 0; Ex = 'Disabled (0)'; S = 'High' }
        @{ A = 'AT'; N = 'Configure LSASS to run as a protected process (LSA Protection)'; P = $lsa; V = 'RunAsPPL'; Op = 'ge'; E = 1; D = $null; Ex = 'Enabled (1 z blokadą UEFI)'; S = 'Medium' }
        @{ A = 'AT'; N = 'Turn off multicast name resolution (LLMNR)'; P = 'Software\Policies\Microsoft\Windows NT\DNSClient'; V = 'EnableMulticast'; Op = 'eq'; E = 0; D = $null; Ex = 'Enabled (0 = LLMNR wyłączony)'; S = 'Medium' }
        @{ A = 'AT'; N = 'NetBT NodeType configuration'; P = 'System\CurrentControlSet\Services\NetBT\Parameters'; V = 'NodeType'; Op = 'eq'; E = 2; D = $null; Ex = 'P-node (2)'; S = 'Low' }
        @{ A = 'AT'; N = 'Enable insecure guest logons (klient SMB)'; P = 'Software\Policies\Microsoft\Windows\LanmanWorkstation'; V = 'AllowInsecureGuestAuth'; Op = 'eq'; E = 0; D = 0; Ex = 'Disabled (0)'; S = 'Medium' }
        @{ A = 'AT'; N = 'Allow Print Spooler to accept client connections'; P = 'Software\Policies\Microsoft\Windows NT\Printers'; V = 'RegisterSpoolerRemoteRpcEndPoint'; Op = 'eq'; E = 2; D = $null; Ex = 'Disabled (2)'; S = 'Low' }
        @{ A = 'AT'; N = 'Encryption Oracle Remediation (CredSSP)'; P = "$polSys\CredSSP\Parameters"; V = 'AllowEncryptionOracle'; Op = 'eq'; E = 0; D = $null; Ex = 'Force Updated Clients (0)'; S = 'Low' }
        @{ A = 'AT'; N = 'RDP: Require user authentication for remote connections by using NLA'; P = $ts; V = 'UserAuthentication'; Op = 'eq'; E = 1; D = $null; Ex = 'Enabled (1)'; S = 'Low' }
        @{ A = 'AT'; N = 'RDP: Do not allow passwords to be saved'; P = $ts; V = 'DisablePasswordSaving'; Op = 'eq'; E = 1; D = $null; Ex = 'Enabled (1)'; S = 'Low' }
        @{ A = 'AT'; N = 'WinRM Service: Allow Basic authentication'; P = "$winrm\Service"; V = 'AllowBasic'; Op = 'eq'; E = 0; D = 0; Ex = 'Disabled (0)'; S = 'Medium' }
        @{ A = 'AT'; N = 'WinRM Service: Allow unencrypted traffic'; P = "$winrm\Service"; V = 'AllowUnencryptedTraffic'; Op = 'eq'; E = 0; D = 0; Ex = 'Disabled (0)'; S = 'Medium' }
        @{ A = 'AT'; N = 'WinRM Client: Allow Basic authentication'; P = "$winrm\Client"; V = 'AllowBasic'; Op = 'eq'; E = 0; D = 0; Ex = 'Disabled (0)'; S = 'Medium' }
        @{ A = 'AT'; N = 'WinRM Client: Allow unencrypted traffic'; P = "$winrm\Client"; V = 'AllowUnencryptedTraffic'; Op = 'eq'; E = 0; D = 0; Ex = 'Disabled (0)'; S = 'Medium' }
        @{ A = 'AT'; N = 'Turn on PowerShell Script Block Logging'; P = 'Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; V = 'EnableScriptBlockLogging'; Op = 'eq'; E = 1; D = $null; Ex = 'Enabled (1)'; S = 'Medium' }
        @{ A = 'AT'; N = 'Include command line in process creation events'; P = "$polSys\Audit"; V = 'ProcessCreationIncludeCmdLine_Enabled'; Op = 'eq'; E = 1; D = $null; Ex = 'Enabled (1)'; S = 'Low' }
        @{ A = 'AT'; N = 'Security event log: Maximum log size (KB)'; P = "$evl\Security"; V = 'MaxSize'; Op = 'ge'; E = 196608; D = $null; Ex = '≥ 196608 KB'; S = 'Medium' }
        @{ A = 'AT'; N = 'Application event log: Maximum log size (KB)'; P = "$evl\Application"; V = 'MaxSize'; Op = 'ge'; E = 32768; D = $null; Ex = '≥ 32768 KB'; S = 'Low' }
        @{ A = 'AT'; N = 'System event log: Maximum log size (KB)'; P = "$evl\System"; V = 'MaxSize'; Op = 'ge'; E = 32768; D = $null; Ex = '≥ 32768 KB'; S = 'Low' }
        @{ A = 'AT'; N = 'Turn off Autoplay (wszystkie napędy)'; P = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'; V = 'NoDriveTypeAutoRun'; Op = 'eq'; E = 255; D = $null; Ex = 'All drives (255)'; S = 'Low' }
    )
    # E: 1 = Success, 2 = Failure, 3 = oba; G = początek GUID podkategorii (reszta: -69ae-11d9-bed3-505054503030)
    $cisAudit = @(
        @{ G = '0cce923f'; N = 'Account Logon: Credential Validation'; E = 3; S = 'Medium' }
        @{ G = '0cce9242'; N = 'Account Logon: Kerberos Authentication Service'; E = 3; S = 'Medium' }
        @{ G = '0cce9240'; N = 'Account Logon: Kerberos Service Ticket Operations'; E = 3; S = 'Medium' }
        @{ G = '0cce9235'; N = 'Account Management: User Account Management'; E = 3; S = 'Medium' }
        @{ G = '0cce9237'; N = 'Account Management: Security Group Management'; E = 1; S = 'Medium' }
        @{ G = '0cce9236'; N = 'Account Management: Computer Account Management'; E = 1; S = 'Low' }
        @{ G = '0cce9238'; N = 'Account Management: Distribution Group Management'; E = 1; S = 'Low' }
        @{ G = '0cce923a'; N = 'Account Management: Other Account Management Events'; E = 1; S = 'Low' }
        @{ G = '0cce922b'; N = 'Detailed Tracking: Process Creation'; E = 1; S = 'Low' }
        @{ G = '0cce9248'; N = 'Detailed Tracking: Plug and Play Events'; E = 1; S = 'Low' }
        @{ G = '0cce923b'; N = 'DS Access: Directory Service Access'; E = 2; S = 'Low' }
        @{ G = '0cce923c'; N = 'DS Access: Directory Service Changes'; E = 1; S = 'Medium' }
        @{ G = '0cce9217'; N = 'Logon/Logoff: Account Lockout'; E = 2; S = 'Medium' }
        @{ G = '0cce9249'; N = 'Logon/Logoff: Group Membership'; E = 1; S = 'Low' }
        @{ G = '0cce9216'; N = 'Logon/Logoff: Logoff'; E = 1; S = 'Low' }
        @{ G = '0cce9215'; N = 'Logon/Logoff: Logon'; E = 3; S = 'Medium' }
        @{ G = '0cce921c'; N = 'Logon/Logoff: Other Logon/Logoff Events'; E = 3; S = 'Low' }
        @{ G = '0cce921b'; N = 'Logon/Logoff: Special Logon'; E = 1; S = 'Medium' }
        @{ G = '0cce922f'; N = 'Policy Change: Audit Policy Change'; E = 1; S = 'Medium' }
        @{ G = '0cce9230'; N = 'Policy Change: Authentication Policy Change'; E = 1; S = 'Low' }
        @{ G = '0cce9228'; N = 'Privilege Use: Sensitive Privilege Use'; E = 3; S = 'Low' }
        @{ G = '0cce9210'; N = 'System: Security State Change'; E = 1; S = 'Low' }
        @{ G = '0cce9211'; N = 'System: Security System Extension'; E = 1; S = 'Medium' }
        @{ G = '0cce9212'; N = 'System: System Integrity'; E = 3; S = 'Low' }
    )
    # Allowed = dozwolone SID-y (pusta lista = nikt); Forbidden = zakazane; Required = wymagane. DA/EA dopuszczone obok Administrators.
    $adm = @('S-1-5-32-544', "$dSid-512", "$dSid-519")
    $cisRights = @(
        @{ R = 'SeTrustedCredManAccessPrivilege'; N = 'Access Credential Manager as a trusted caller'; Allowed = @(); S = 'Medium' }
        @{ R = 'SeTcbPrivilege'; N = 'Act as part of the operating system'; Allowed = @(); S = 'High' }
        @{ R = 'SeCreateTokenPrivilege'; N = 'Create a token object'; Allowed = @(); S = 'High' }
        @{ R = 'SeNetworkLogonRight'; N = 'Access this computer from the network'; Forbidden = @('S-1-1-0', 'S-1-5-7', 'S-1-5-32-546', 'S-1-5-32-554'); S = 'Low' }
        @{ R = 'SeMachineAccountPrivilege'; N = 'Add workstations to domain'; Allowed = $adm; S = 'Medium' }
        @{ R = 'SeInteractiveLogonRight'; N = 'Allow log on locally'; Allowed = ($adm + 'S-1-5-9'); S = 'Medium' }
        @{ R = 'SeRemoteInteractiveLogonRight'; N = 'Allow log on through Remote Desktop Services'; Allowed = $adm; S = 'Medium' }
        @{ R = 'SeBackupPrivilege'; N = 'Back up files and directories'; Allowed = $adm; S = 'Low' }
        @{ R = 'SeRestorePrivilege'; N = 'Restore files and directories'; Allowed = $adm; S = 'Low' }
        @{ R = 'SeDebugPrivilege'; N = 'Debug programs'; Allowed = $adm; S = 'Medium' }
        @{ R = 'SeLoadDriverPrivilege'; N = 'Load and unload device drivers'; Allowed = $adm; S = 'Medium' }
        @{ R = 'SeTakeOwnershipPrivilege'; N = 'Take ownership of files or other objects'; Allowed = $adm; S = 'Low' }
        @{ R = 'SeEnableDelegationPrivilege'; N = 'Enable computer and user accounts to be trusted for delegation'; Allowed = $adm; S = 'Medium' }
        @{ R = 'SeSecurityPrivilege'; N = 'Manage auditing and security log'; Allowed = $adm; S = 'Low' }
        @{ R = 'SeDenyNetworkLogonRight'; N = 'Deny access to this computer from the network'; Required = @('S-1-5-32-546'); S = 'Low' }
        @{ R = 'SeDenyInteractiveLogonRight'; N = 'Deny log on locally'; Required = @('S-1-5-32-546'); S = 'Low' }
    )
    $auditTxt = @{ 0 = 'brak'; 1 = 'Success'; 2 = 'Failure'; 3 = 'Success and Failure' }
    $cisRows  = [System.Collections.Generic.List[object]]::new()

    Invoke-Check 'CIS' {
        $gpo = Get-DcGpoPolicy

        # Cele oceny: przy -UseWinRM każdy DC osobno (rejestr + auditpol), inaczej jeden zestaw z GPO dla wszystkich DC
        $targets = [System.Collections.Generic.List[object]]::new()
        if ($UseWinRM) {
            $paths = [string[]]@($cisReg | ForEach-Object { "$($_.P)|$($_.V)" })
            foreach ($dc in $dcs) {
                try {
                    $r = Invoke-Command -ComputerName $dc.HostName -ErrorAction Stop -ArgumentList (, $paths) -ScriptBlock {
                        param([string[]]$Paths)
                        $reg = @{}
                        foreach ($p in $Paths) {
                            $k, $n = $p -split '\|', 2
                            $item = Get-ItemProperty -LiteralPath "HKLM:\$k" -Name $n -ErrorAction SilentlyContinue
                            if ($item) { $reg[$p] = $item.$n }
                        }
                        $aud = @(auditpol.exe /get /category:* /r | ConvertFrom-Csv | ForEach-Object { [pscustomobject]@{ G = $_.'Subcategory GUID'; S = $_.'Inclusion Setting' } })
                        [pscustomobject]@{ Reg = $reg; Audit = $aud }
                    }
                    $targets.Add([pscustomobject]@{ DC = $dc.HostName; Tryb = 'WinRM'; Reg = $r.Reg; Audit = @($r.Audit) })
                } catch {
                    $targets.Add([pscustomobject]@{ DC = "$($dc.HostName) (GPO - WinRM niedostępny)"; Tryb = 'GPO'; Reg = $null; Audit = $null })
                }
            }
        } else {
            $targets.Add([pscustomobject]@{ DC = 'wszystkie DC (GPO)'; Tryb = 'GPO'; Reg = $null; Audit = $null })
        }

        foreach ($t in $targets) {
            foreach ($c in $cisReg) {
                if ($t.Tryb -eq 'WinRM') {
                    $val = $t.Reg["$($c.P)|$($c.V)"]
                    $src = if ($null -ne $val) { 'rejestr DC (WinRM)' } else { 'nieustawione - wartość domyślna systemu' }
                } else {
                    $g = $gpo.Registry["$($c.P)\$($c.V)".ToLower()]
                    $val = if ($g) { $g.Wartosc } else { $null }
                    $src = if ($g) { $g.Zrodlo } else { 'brak w GPO - wartość domyślna systemu' }
                }
                $row = [pscustomobject]@{
                    Ustawienie = $c.N; DC = $t.DC; Obszar = $(if ($c.A -eq 'SO') { 'Opcje zabezpieczeń' } else { 'Szablony administracyjne' })
                    Oczekiwane = $c.Ex; Aktualne = $(if ($null -ne $val) { "$val" } elseif ($null -ne $c.D) { "nieustawione (domyślnie $($c.D))" } else { 'nieustawione' })
                    Zrodlo = $src; Waga = $c.S; Zgodne = $(if (Test-CisValue $val $c) { 'Tak' } else { 'Nie' })
                }
                $cisRows.Add($row)
            }
            foreach ($a in $cisAudit) {
                $guid = "$($a.G)-69ae-11d9-bed3-505054503030"
                if ($t.Tryb -eq 'WinRM') {
                    $line = $t.Audit | Where-Object { "$($_.G)".Trim('{', '}').ToLower() -eq $guid } | Select-Object -First 1
                    $val = if ($line) { ConvertFrom-AuditText $line.S } else { $null }
                    $src = 'auditpol (WinRM)'
                } else {
                    $g = $gpo.Audit[$guid]
                    $val = if ($g) { $g.Wartosc } else { $null }
                    $src = if ($g) { $g.Zrodlo } elseif ($gpo.Audit.Count) { 'brak w GPO' } else { 'brak zaawansowanych zasad audytu w GPO' }
                }
                $row = [pscustomobject]@{
                    Ustawienie = $a.N; DC = $t.DC; Obszar = 'Zasady audytu'
                    Oczekiwane = $auditTxt[$a.E]; Aktualne = $(if ($null -ne $val) { $auditTxt[[int]$val] } else { 'nieustawione' })
                    Zrodlo = $src; Waga = $a.S; Zgodne = $(if ($null -ne $val -and (([int]$val -band $a.E) -eq $a.E)) { 'Tak' } else { 'Nie' })
                }
                $cisRows.Add($row)
            }
        }

        foreach ($c in $cisRights) {
            $g = $gpo.Rights[$c.R]
            $exp = if ($c.ContainsKey('Allowed')) { if ($c.Allowed.Count) { 'tylko: ' + (($c.Allowed | ForEach-Object { Resolve-SidName $_ }) -join ', ') } else { 'nikt' } }
                   elseif ($c.ContainsKey('Forbidden')) { 'bez: ' + (($c.Forbidden | ForEach-Object { Resolve-SidName $_ }) -join ', ') }
                   else { 'zawiera: ' + (($c.Required | ForEach-Object { Resolve-SidName $_ }) -join ', ') }
            if (-not $g) {
                $ok  = if ($c.ContainsKey('Allowed') -and $c.Allowed.Count -eq 0) { 'Tak' } else { 'nie oceniono' }
                $cur = 'brak w GPO'; $src = 'brak w GPO - wartość domyślna systemu'
            } else {
                $sids = @($g.Wartosc)
                $bad  = @()
                if ($c.ContainsKey('Allowed'))   { $bad += @($sids | Where-Object { $_ -notin $c.Allowed }) }
                if ($c.ContainsKey('Forbidden')) { $bad += @($sids | Where-Object { $_ -in $c.Forbidden }) }
                $miss = @(); if ($c.ContainsKey('Required')) { $miss = @($c.Required | Where-Object { $_ -notin $sids }) }
                $ok  = if ($bad.Count -eq 0 -and $miss.Count -eq 0) { 'Tak' } else { 'Nie' }
                $cur = if ($sids.Count) { ($sids | ForEach-Object { Resolve-SidName $_ }) -join ', ' } else { '(nikt)' }
                $src = $g.Zrodlo
            }
            $row = [pscustomobject]@{
                Ustawienie = "$($c.N) ($($c.R))"; DC = 'wszystkie DC (GPO)'; Obszar = 'Przypisanie praw użytkowników'
                Oczekiwane = $exp; Aktualne = $cur; Zrodlo = $src; Waga = $c.S; Zgodne = $ok
            }
            $cisRows.Add($row)
        }

        $fail  = @($cisRows | Where-Object Zgodne -eq 'Nie')
        $regF  = @($fail | Where-Object { $_.Obszar -in 'Opcje zabezpieczeń', 'Szablony administracyjne' })
        $audF  = @($fail | Where-Object Obszar -eq 'Zasady audytu')
        $rigF  = @($fail | Where-Object Obszar -eq 'Przypisanie praw użytkowników')
        $gpoNote = if ($UseWinRM) { 'Wartości odczytano z rejestru i auditpol każdego DC (stan rzeczywisty).' } else { 'Wartości odczytano z GPO podlinkowanych do domeny i OU Domain Controllers (konfiguracja zamierzona); ustawienia lokalne DC mogą się różnić - dokładny stan daje -UseWinRM.' }

        Add-IfAny @{
            Id = 'DC-CIS-REG'; Category = $catCis; Severity = (Get-TopSeverity $regF)
            Title = 'Opcje zabezpieczeń i szablony administracyjne DC niezgodne z CIS L1'
            Objects = $regF
            Description = "Ustawienia zabezpieczeń kontrolerów domeny odbiegają od CIS Benchmark (profil L1 dla DC): m.in. ochrona poświadczeń (WDigest, LSA Protection), podpisywanie SMB, szyfrowanie Kerberos, rozwiązywanie nazw (LLMNR), WinRM i logowanie PowerShell. $gpoNote"
            Recommendation = 'Ustawienia wprowadzać w GPO podlinkowanym do OU Domain Controllers (nie w Default Domain Policy), etapami i po teście. Punktem wyjścia może być Microsoft Security Baseline dla DC (Security Compliance Toolkit). Zmiany SMB signing, Kerberos AES-only i LSA Protection wymagają wcześniejszej weryfikacji zgodności aplikacji.'
            Fix = (Fx '# GPMC > GPO dla OU Domain Controllers > Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options', '# oraz Administrative Templates (ścieżki: nazwy ustawień w kolumnie Ustawienie)', 'gpresult /h C:\Temp\dc-gpo.html   # na DC: zastosowane ustawienia')
        }
        Add-IfAny @{
            Id = 'DC-CIS-AUDIT'; Category = $catCis; Severity = (Get-TopSeverity $audF)
            Title = 'Zasady audytu DC niezgodne z CIS L1'
            Objects = $audF
            Description = "Brak audytu tych zdarzeń oznacza, że logowania, zmiany grup uprzywilejowanych, zmiany w AD i użycie uprawnień nie zostaną zarejestrowane - SIEM/SOC nie wykryje ataku, a analiza incydentu będzie niemożliwa. $gpoNote"
            Recommendation = 'Skonfigurować Advanced Audit Policy Configuration w GPO dla OU Domain Controllers i włączyć "Audit: Force audit policy subcategory settings". Zwiększyć rozmiar dziennika Security i przekazywać zdarzenia do SIEM.'
            Fix = (Fx '# GPMC > GPO dla OU Domain Controllers > Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration', 'auditpol /get /category:*   # na DC: stan rzeczywisty')
            Mitre = 'T1562.002'
        }
        Add-IfAny @{
            Id = 'DC-CIS-RIGHTS'; Category = $catCis; Severity = (Get-TopSeverity $rigF)
            Title = 'Przypisanie praw użytkowników na DC niezgodne z CIS L1'
            Objects = $rigF
            Description = 'Prawa takie jak logowanie lokalne lub przez RDP na DC, ładowanie sterowników, kopia zapasowa/przywracanie plików czy debugowanie programów pozwalają przejąć kontroler domeny. Domyślna Default Domain Controllers Policy nadaje część z nich grupom operatorów (Account/Server/Print/Backup Operators).'
            Recommendation = 'Ograniczyć prawa do Administrators zgodnie z kolumną Oczekiwane; grupy operatorów pozostawić puste. Zmieniać w GPO dla OU Domain Controllers.'
            Fix = (Fx '# GPMC > Default Domain Controllers Policy (lub dedykowane GPO) > Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > User Rights Assignment')
            Mitre = 'T1078.002'
        }
        $evaluated = @($cisRows | Where-Object { $_.Zgodne -in 'Tak', 'Nie' })
        $okCount   = @($evaluated | Where-Object Zgodne -eq 'Tak').Count
        $pct       = if ($evaluated.Count) { [int](100 * $okCount / $evaluated.Count) } else { 0 }
        Add-Finding @{
            Id = 'DC-CIS-SUMMARY'; Category = $catCis; Severity = 'Info'
            Title = "Zgodność DC z wybranymi kontrolami CIS L1: $okCount z $($evaluated.Count) ($pct%)"
            Objects = $cisRows
            Description = "Pełna lista sprawdzonych ustawień ze statusem. Kontrole wybrane na podstawie CIS Microsoft Windows Server Benchmark (profil L1, kontroler domeny); nie jest to pełna ocena zgodności z CIS. $gpoNote"
        }
    }
}
#endregion

#region ---------- kondycja domeny i replikacja ----------
# Wszystko zwykłym kontem: metadane replikacji przez ADWS, SYSVOL przez SMB, czas przez NTP (w32tm), DNS przez resolver stacji.
$healthUnk = [System.Collections.Generic.List[object]]::new()
$replErr = @{
    5 = 'odmowa dostępu'; 1256 = 'system zdalny niedostępny'; 1396 = 'błąd logowania (SPN / konto komputera partnera)'
    1722 = 'serwer RPC niedostępny (sieć, zapora, DC wyłączony)'; 1727 = 'zdalne wywołanie procedury nie powiodło się'
    1908 = 'nie znaleziono kontrolera domeny'; 8453 = 'odmowa dostępu do replikacji'; 8456 = 'źródłowy DC odrzuca replikację'
    8457 = 'docelowy DC odrzuca replikację'; 8524 = 'błąd DNS - nie można rozwiązać nazwy partnera'
    8606 = 'obiekty zalegające (lingering objects)'; 8614 = 'przekroczony tombstone lifetime - DC odcięty zbyt długo'
}

Invoke-Check 'REPL' {
    $tsl = (Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,$($rootDse.configurationNamingContext)" -Properties tombstoneLifetime -Server $Server).tombstoneLifetime
    if (-not $tsl) { $tsl = 60 }
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($dc in $dcs) {
        try {
            foreach ($m in @(Get-ADReplicationPartnerMetadata -Target $dc.HostName -Partition * -ErrorAction Stop)) {
                $code = [int]$m.LastReplicationResult
                $rows.Add([pscustomobject]@{
                    DC            = $dc.HostName
                    Partner       = ((($m.Partner -split ',')[1]) -replace '^CN=', '')   # nawiasy wymagane: hashtable wewnątrz .Add(), przecinek = separator argumentów
                    Partycja      = (Get-NcName $m.Partition)
                    OstatniSukces = $(if ($m.LastReplicationSuccess) { $m.LastReplicationSuccess.ToString('yyyy-MM-dd HH:mm') } else { 'nigdy' })
                    KolejneBledy  = $m.ConsecutiveReplicationFailureCount
                    KodBledu      = $code
                    Opis          = $(if ($code -eq 0) { '' } elseif ($replErr.ContainsKey($code)) { $replErr[$code] } else { "net helpmsg $code" })
                    Sukces        = $m.LastReplicationSuccess
                })
            }
        } catch {
            $healthUnk.Add([pscustomobject]@{ DC = $dc.HostName; Test = 'Replikacja'; Blad = $_.Exception.Message })
        }
    }
    $out = { $_ | Select-Object -Property * -ExcludeProperty Sukces }

    Add-IfAny @{
        Id = 'DC-REPL-FAIL'; Category = $catHealth; Severity = 'High'
        Title = 'Błędy replikacji AD'
        Objects = ($rows | Where-Object { $_.KodBledu -ne 0 -or $_.KolejneBledy -gt 0 } | ForEach-Object $out)
        Description = 'Kontrolery domeny nie wymieniają zmian. Skutki: niespójne hasła i członkostwa w grupach, wyłączone konta nadal aktywne na części DC, niezastosowane GPO, a w skrajnym przypadku utrata DC.'
        Recommendation = 'Usunąć przyczynę z kolumny Opis (najczęściej DNS, zapora, wyłączony lub odtworzony z migawki DC), potem wymusić replikację i sprawdzić ponownie.'
        Fix = (Fx 'repadmin /replsummary', 'repadmin /showrepl * /errorsonly', 'dcdiag /e /test:replications /test:dns', 'repadmin /syncall /AdeP   # po usunięciu przyczyny')
    }
    Add-IfAny @{
        Id = 'DC-REPL-STALE'; Category = $catHealth; Severity = 'High'
        Title = 'Replikacja AD nieudana od ponad 24 godzin'
        Objects = ($rows | Where-Object { $_.Sukces -and $_.Sukces -lt $now.AddHours(-24) -and $_.Sukces -ge $now.AddDays(-$tsl) } | ForEach-Object $out)
        Description = "Ostatnia udana replikacja z partnerem była ponad dobę temu. Jeśli przekroczy tombstone lifetime ($tsl dni), DC trzeba będzie usunąć i promować od nowa."
        Recommendation = 'Ustalić przyczynę (kolumny KodBledu/Opis, dcdiag) i przywrócić replikację, zanim upłynie tombstone lifetime.'
        Fix = (Fx 'repadmin /showrepl <DC>', 'dcdiag /s:<DC> /v')
    }
    Add-IfAny @{
        Id = 'DC-REPL-TSL'; Category = $catHealth; Severity = 'Critical'
        Title = "Replikacja AD nieudana dłużej niż tombstone lifetime ($tsl dni)"
        Objects = ($rows | Where-Object { $_.Sukces -and $_.Sukces -lt $now.AddDays(-$tsl) } | ForEach-Object $out)
        Description = 'DC nie replikował dłużej niż czas przechowywania usuniętych obiektów. Ponowne włączenie replikacji grozi przywróceniem usuniętych kont i obiektów (lingering objects).'
        Recommendation = 'Nie wymuszać replikacji. Odłączyć DC, usunąć jego metadane (ntdsutil metadata cleanup lub konsola ADUC), zainstalować i promować ponownie.'
        Fix = (Fx '# NIE uruchamiać repadmin /syncall - najpierw izolacja DC', 'repadmin /removelingeringobjects <DC_docelowy> <GUID_DC_referencyjnego> <partycja> /advisory_mode')
    }
    if ($dcs.Count -eq 1) {
        Add-Finding @{
            Id = 'D-SINGLEDC'; Category = $catHealth; Severity = 'Medium'
            Title = 'Domena ma tylko jeden kontroler domeny'
            Objects = ($dcs | ForEach-Object { [pscustomobject]@{ DC = $_.HostName; System = $_.OperatingSystem } })
            Description = 'Awaria jedynego DC zatrzymuje logowanie, DNS, GPO i dostęp do zasobów; odtworzenie zależy wyłącznie od kopii zapasowej.'
            Recommendation = 'Dodać drugi kontroler domeny (najlepiej na innym hoście fizycznym/wirtualizacji) z rolą DNS i Global Catalog.'
            Fix = (Fx 'Install-ADDSDomainController -DomainName {DOMENA} -InstallDns   # na nowym serwerze')
        }
    }
}

Invoke-Check 'BACKUP' {
    $md = Get-ADReplicationAttributeMetadata -Object $domain.DistinguishedName -Properties dSASignature -Server $Server |
          Where-Object AttributeName -eq 'dSASignature' | Select-Object -First 1
    $last = if ($md) { $md.LastOriginatingChangeTime } else { $null }
    if (-not $last -or $last -lt $now.AddDays(-7)) {
        $txt = if ($last) { "ostatnia zarejestrowana: $(Format-Date $last), $([int]($now - $last).TotalDays) dni temu" } else { 'brak śladu kopii' }
        Add-Finding @{
            Id = 'D-BACKUP'; Category = $catHealth; Severity = 'High'
            Title = "Brak aktualnej kopii zapasowej AD ($txt)"
            Description = 'AD zapisuje datę ostatniej kopii wykonanej świadomie dla AD (VSS writer NTDS). Bez aktualnej kopii nie da się odtworzyć domeny po awarii, ransomware ani usunięciu obiektów. Uwaga: kopia całej maszyny wirtualnej bez przetwarzania aplikacyjnego (application-aware) nie aktualizuje tej daty i nie zawsze nadaje się do odtworzenia DC.'
            Recommendation = 'Wykonywać codzienną kopię stanu systemu (System State) co najmniej dwóch DC lub kopię VM z przetwarzaniem aplikacyjnym; okresowo testować odtworzenie.'
            Fix = (Fx 'wbadmin start systemstatebackup -backupTarget:<dysk>: -quiet   # na DC, przykład bez oprogramowania backupowego', 'repadmin /showbackup *')
            Mitre = 'T1490'
        }
    }
}

Invoke-Check 'SYSVOL-FRS' {
    Add-IfAny @{
        Id = 'D-SYSVOL-FRS'; Category = $catHealth; Severity = 'High'
        Title = 'SYSVOL replikowany przez przestarzały FRS'
        Objects = ($dcs | Where-Object {
                      -not (Get-ADObject -SearchBase $_.ComputerObjectDN -LDAPFilter '(&(objectClass=msDFSR-Subscription)(name=SYSVOL Subscription))' -Server $Server)
                  } | ForEach-Object { [pscustomobject]@{ DC = $_.HostName; System = $_.OperatingSystem; Mechanizm = 'FRS (brak subskrypcji DFSR dla SYSVOL)' } })
        Description = 'FRS jest wycofany i zawodny (rozjeżdżające się GPO i skrypty). Nowych DC z Windows Server 2019+ nie da się dodać do domeny z SYSVOL na FRS.'
        Recommendation = 'Przeprowadzić migrację SYSVOL do DFSR (dfsrmig: Prepared, Redirected, Eliminated) przy zdrowej replikacji AD.'
        Fix = (Fx 'dfsrmig /getglobalstate', 'dfsrmig /setglobalstate 1   # potem 2 i 3, po każdym kroku dfsrmig /getmigrationstate')
    }
}

Invoke-Check 'FSMO' {
    $dn = $domain.DistinguishedName
    $roles = [ordered]@{
        'PDC Emulator' = $dn; 'RID Master' = "CN=RID Manager`$,CN=System,$dn"; 'Infrastructure Master' = "CN=Infrastructure,$dn"
        'Schema Master' = $rootDse.schemaNamingContext; 'Domain Naming Master' = "CN=Partitions,$($rootDse.configurationNamingContext)"
    }
    $dcNames = @($dcs | ForEach-Object { $_.Name })
    Add-IfAny @{
        Id = 'D-FSMO'; Category = $catHealth; Severity = 'Critical'
        Title = 'Role FSMO przypisane do nieistniejącego kontrolera domeny'
        Objects = @(foreach ($r in $roles.GetEnumerator()) {
            $owner = (Get-ADObject -Identity $r.Value -Properties fSMORoleOwner -Server $Server).fSMORoleOwner
            $srv   = (($owner -split ',')[1]) -replace '^CN=', ''
            $domainRole = $r.Key -in 'PDC Emulator','RID Master','Infrastructure Master'
            if ($owner -match 'DEL:' -or ($domainRole -and $srv -notin $dcNames)) {
                [pscustomobject]@{ Rola = $r.Key; Wlasciciel = $owner }
            }
        })
        Description = 'Rola jest przypisana do usuniętego lub nieistniejącego DC. Zależnie od roli: brak puli RID (nie da się tworzyć kont), problemy z czasem i zmianą haseł (PDC), brak zmian schematu lub domen.'
        Recommendation = 'Przejąć rolę (seize) na działającym DC - tylko jeśli poprzedni właściciel na pewno nie wróci do sieci.'
        Fix = (Fx 'netdom query fsmo', 'Move-ADDirectoryServerOperationMasterRole -Identity <DC> -OperationMasterRole <rola> -Force   # seize')
    }
}

Invoke-Check 'DC-MACHINEPWD' {
    Add-IfAny @{
        Id = 'DC-MACHINEPWD'; Category = $catHealth; Severity = 'Medium'
        Title = 'Kontrolery domeny z hasłem konta komputera starszym niż 45 dni'
        Objects = ($dcs | ForEach-Object {
            $c = Get-ADComputer -Identity $_.ComputerObjectDN -Properties PasswordLastSet, LastLogonDate -Server $Server
            if ($c.PasswordLastSet -lt $now.AddDays(-45)) {
                [pscustomobject]@{ DC = $_.HostName; HasloKontaUstawione = Format-Date $c.PasswordLastSet; OstatnieLogowanie = Format-Date $c.LastLogonDate }
            } })
        Description = 'DC zmienia hasło swojego konta co 30 dni. Brak zmiany oznacza zwykle DC wyłączony, odcięty od replikacji, odtworzony z migawki lub z wyłączoną zmianą hasła - wszystkie wymagają wyjaśnienia.'
        Recommendation = 'Sprawdzić, czy DC działa i replikuje; jeśli DC już nie istnieje - usunąć jego metadane.'
        Fix = (Fx 'dcdiag /s:<DC> /test:machineaccount', 'nltest /sc_verify:{DOMENA} /server:<DC>')
    }
}

if (-not $SkipDCChecks) {
    $smbDcs = [System.Collections.Generic.List[object]]::new()   # DC z działającym SMB - dla testu GPO

    Invoke-Check 'DC-NET' {
        $portRows  = [System.Collections.Generic.List[object]]::new()
        $shareRows = [System.Collections.Generic.List[object]]::new()
        $offsets   = @{}
        foreach ($dc in $dcs) {
            $h = $dc.HostName
            $ports = [ordered]@{ '53' = 'DNS'; '88' = 'Kerberos'; '135' = 'RPC'; '389' = 'LDAP'; '445' = 'SMB'; '9389' = 'ADWS' }
            if ($dc.IsGlobalCatalog) { $ports['3268'] = 'Global Catalog' }
            $closed = @(foreach ($k in $ports.Keys) { if (-not (Test-TcpPort -Computer $h -Port ([int]$k))) { "$k ($($ports[$k]))" } })
            if ($closed.Count) { $portRows.Add([pscustomobject]@{ DC = $h; NiedostepnePorty = ($closed -join ', ') }) }

            if (-not ($closed | Where-Object { $_ -like '445 *' })) {
                $smbDcs.Add($dc)
                $miss = @(foreach ($sh in 'SYSVOL', 'NETLOGON') { if (-not [System.IO.Directory]::Exists("\\$h\$sh")) { $sh } })
                if ($miss.Count) { $shareRows.Add([pscustomobject]@{ DC = $h; BrakUdzialu = ($miss -join ', ') }) }
            }

            # Przesunięcie czasu przez NTP (UDP 123); wynik względem stacji, potem przeliczany względem PDC
            $w = (& w32tm.exe /stripchart "/computer:$h" /samples:1 /dataonly 2>$null) -join "`n"
            $mt = [regex]::Match($w, '([+-]\d+[\.,]\d+)s')
            if ($mt.Success) { $offsets[$h] = [double]($mt.Groups[1].Value -replace ',', '.') }
            else { $healthUnk.Add([pscustomobject]@{ DC = $h; Test = 'Czas (NTP, UDP 123)'; Blad = 'brak odpowiedzi' }) }
        }

        Add-IfAny @{
            Id = 'DC-PORTS'; Category = $catHealth; Severity = 'Medium'
            Title = 'Kontrolery domeny z niedostępnymi usługami'
            Objects = $portRows
            Description = 'Ze stacji, z której wykonano przegląd, nie odpowiadają porty usług AD. Klienci w tej samej sieci mogą mieć problemy z logowaniem, GPO lub DNS. Przyczyną może też być zapora między stacją a DC - wynik należy porównać z innej podsieci.'
            Recommendation = 'Sprawdzić, czy usługi działają na DC (DNS, KDC, Netlogon, ADWS) i czy zapora przepuszcza ruch AD z sieci klienckich.'
            Fix = (Fx 'dcdiag /s:<DC> /test:services /test:advertising', 'Test-NetConnection <DC> -Port <port>')
        }
        Add-IfAny @{
            Id = 'DC-SYSVOL-SHARE'; Category = $catHealth; Severity = 'High'
            Title = 'Kontrolery domeny bez udziału SYSVOL lub NETLOGON'
            Objects = $shareRows
            Description = 'DC bez udziałów SYSVOL/NETLOGON nie dostarcza GPO ani skryptów logowania i nie ogłasza się jako pełnoprawny DC. Zwykle oznacza nieukończoną początkową replikację SYSVOL (DFSR) lub błąd po odtworzeniu DC.'
            Recommendation = 'Sprawdzić stan replikacji SYSVOL (zdarzenia DFS Replication 4614/4604, 2213) i wartość SysvolReady na DC.'
            Fix = (Fx 'dcdiag /s:<DC> /test:netlogons /test:sysvolcheck', 'reg query HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters /v SysvolReady   # na DC', 'wmic /namespace:\\root\microsoftdfs path dfsrreplicatedfolderinfo get replicatedfoldername,state   # na DC')
        }

        $pdc = $domain.PDCEmulator
        if ($offsets.Count -gt 1 -and $offsets.ContainsKey($pdc)) {
            $ref = $offsets[$pdc]
            $timeRows = @(foreach ($k in $offsets.Keys) {
                $d = [math]::Round($offsets[$k] - $ref, 1)
                if ([math]::Abs($d) -gt 60) { [pscustomobject]@{ DC = $k; RoznicaWzgledemPDC_s = $d } }
            })
            Add-IfAny @{
                Id = 'DC-TIME'; Category = $catHealth
                Severity = $(if (@($timeRows | Where-Object { [math]::Abs($_.RoznicaWzgledemPDC_s) -gt 300 }).Count) { 'High' } else { 'Medium' })
                Title = 'Czas kontrolerów domeny różni się od PDC o ponad minutę'
                Objects = $timeRows
                Description = 'Kerberos odrzuca uwierzytelnienie przy różnicy czasu powyżej 5 minut. Rozjechany czas DC powoduje losowe błędy logowania i replikacji.'
                Recommendation = 'DC synchronizują czas z hierarchii domeny (NT5DS), a tylko PDC Emulator z zewnętrznego źródła NTP. Na maszynach wirtualnych wyłączyć synchronizację czasu z hypervisorem.'
                Fix = (Fx 'w32tm /config /syncfromflags:domhier /update   # na DC innym niż PDC', 'w32tm /config /manualpeerlist:"0.pl.pool.ntp.org 1.pl.pool.ntp.org" /syncfromflags:manual /reliable:yes /update   # na PDC', 'w32tm /resync /rediscover')
            }
        }
    }

    Invoke-Check 'GPO-SYNC' {
        $gpos = @(Get-ADObject -SearchBase "CN=Policies,CN=System,$($domain.DistinguishedName)" -SearchScope OneLevel `
                  -LDAPFilter '(objectClass=groupPolicyContainer)' -Properties displayName, versionNumber -Server $Server)
        $rows = foreach ($dc in $smbDcs) {
            foreach ($g in $gpos) {
                $ini = "\\$($dc.HostName)\SYSVOL\$($domain.DNSRoot)\Policies\$($g.Name)\GPT.INI"
                try {
                    $line = Get-Content -LiteralPath $ini -ErrorAction Stop | Where-Object { $_ -match '^\s*Version\s*=' } | Select-Object -First 1
                    $v = if ($line) { [int](($line -split '=', 2)[1].Trim()) } else { 'brak wersji' }
                }
                catch [System.Management.Automation.ItemNotFoundException] { $v = 'brak folderu GPO' }
                catch { continue }   # brak dostępu do odczytu - pomijamy
                if ("$v" -ne "$($g.versionNumber)") {
                    [pscustomobject]@{ GPO = $g.displayName; Guid = $g.Name; DC = $dc.HostName; WersjaAD = $g.versionNumber; WersjaSYSVOL = $v }
                }
            }
        }
        Add-IfAny @{
            Id = 'D-GPO-SYNC'; Category = $catHealth; Severity = 'Medium'
            Title = 'GPO niespójne między AD a SYSVOL'
            Objects = $rows
            Description = 'Wersja GPO zapisana w AD różni się od pliku GPT.INI w SYSVOL na kontrolerze domeny (lub folderu GPO brak). Komputery mogą otrzymywać nieaktualne lub różne ustawienia zależnie od DC. Pojedyncze różnice zaraz po edycji GPO są normalne - liczy się stan utrzymujący się.'
            Recommendation = 'Sprawdzić replikację SYSVOL (DFSR) i AD; jeśli różnice się utrzymują - wykonać nieautorytatywną synchronizację SYSVOL na problematycznym DC.'
            Fix = (Fx 'dcdiag /e /test:sysvolcheck /test:frssysvol', '# konsola GPMC > Status (Infrastructure Status) dla domeny', '# nieautorytatywna synchronizacja DFSR: msDFSR-Enabled=FALSE/TRUE na subskrypcji SYSVOL problematycznego DC (KB2218556)')
        }
    }

    Invoke-Check 'DC-DNS' {
        $srv = @(Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$($domain.DNSRoot)" -Type SRV -ErrorAction Stop |
                 Where-Object { $_.Type -eq 'SRV' } | ForEach-Object { $_.NameTarget.TrimEnd('.') })
        Add-IfAny @{
            Id = 'DC-DNS-SRV'; Category = $catHealth; Severity = 'Medium'
            Title = 'Kontrolery domeny bez rekordu SRV w DNS'
            Objects = ($dcs | Where-Object { $_.HostName -notin $srv } | ForEach-Object { [pscustomobject]@{ DC = $_.HostName; Lokacja = $_.Site } })
            Description = 'Klienci odnajdują kontrolery domeny przez rekordy SRV w DNS. DC bez rekordu nie jest używany do logowania, a jeśli DC już nie istnieje - jego brak może oznaczać nieusunięte metadane w AD.'
            Recommendation = 'Na DC zrestartować usługę Netlogon (rejestruje rekordy SRV) i sprawdzić, czy DC używa poprawnych serwerów DNS; nieistniejące DC usunąć z AD.'
            Fix = (Fx 'nltest /dsregdns   # na DC', 'Restart-Service Netlogon   # na DC', 'dcdiag /s:<DC> /test:dns /dnsrecordregistration')
        }
    }
}

Add-IfAny @{
    Id = 'HEALTH-UNKNOWN'; Category = 'Błędy testów'; Severity = 'Info'; Title = 'Testy kondycji nierozstrzygnięte'; Objects = $healthUnk
    Description = 'Nie udało się odczytać części danych (brak łączności, zapora lub brak dostępu). Powtórzyć z innej stacji.'
}
#endregion

#region ---------- wynik: dane ----------
$sevOrder = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
$sorted   = @($findings | Sort-Object { $sevOrder[$_.Severity] }, Category, Id)
$real     = @($sorted | Where-Object Severity -ne 'Info')
$score    = [int](($findings | ForEach-Object { $weights[$_.Severity] } | Measure-Object -Sum).Sum)
$sevCount = @{}
foreach ($s in 'Critical','High','Medium','Low') { $sevCount[$s] = @($real | Where-Object Severity -eq $s).Count }

$summary = @($real | Group-Object Category | ForEach-Object {
    $g = $_.Group
    [pscustomobject]@{
        Kategoria = $_.Name
        Critical  = @($g | Where-Object Severity -eq 'Critical').Count
        High      = @($g | Where-Object Severity -eq 'High').Count
        Medium    = @($g | Where-Object Severity -eq 'Medium').Count
        Low       = @($g | Where-Object Severity -eq 'Low').Count
        Punkty    = [int](($g | ForEach-Object { $weights[$_.Severity] } | Measure-Object -Sum).Sum)
    }
} | Sort-Object Punkty -Descending)

$diff = $null
if ($Previous) {
    $prev    = Get-Content $Previous -Raw -Encoding UTF8 | ConvertFrom-Json
    $prevIds = @($prev.Znaleziska | Where-Object Severity -ne 'Info' | ForEach-Object { $_.Id })
    $currIds = @($real | ForEach-Object { $_.Id })
    $diff = [ordered]@{
        PoprzedniaData  = $prev.Meta.Data
        PoprzedniWynik  = $prev.Meta.Wynik
        Nowe            = @($currIds | Where-Object { $_ -notin $prevIds })
        Usuniete        = @($prevIds | Where-Object { $_ -notin $currIds })
    }
}

$meta = [ordered]@{
    Klient    = $Klient
    Domena    = $domain.DNSRoot
    Data      = $now.ToString('s')
    Wynik     = $score
    Wersja    = $Version
    DC        = @($dcs.HostName)
    Uruchomil = "$env:USERDOMAIN\$env:USERNAME"
    Stacja    = $env:COMPUTERNAME
    TestyDC   = $dcMethod
}

$invDomain = @(
    [pscustomobject]@{ Parametr = 'Domena (DNS / NetBIOS)';      Wartosc = "$($domain.DNSRoot) / $($domain.NetBIOSName)" }
    [pscustomobject]@{ Parametr = 'Las';                          Wartosc = $forest.Name }
    [pscustomobject]@{ Parametr = 'Poziom funkcjonalny domeny';   Wartosc = "$($domain.DomainMode)" }
    [pscustomobject]@{ Parametr = 'Poziom funkcjonalny lasu';     Wartosc = "$($forest.ForestMode)" }
    [pscustomobject]@{ Parametr = 'PDC Emulator';                 Wartosc = $domain.PDCEmulator }
    [pscustomobject]@{ Parametr = 'RID Master';                   Wartosc = $domain.RIDMaster }
    [pscustomobject]@{ Parametr = 'Infrastructure Master';        Wartosc = $domain.InfrastructureMaster }
    [pscustomobject]@{ Parametr = 'Schema Master';                Wartosc = $forest.SchemaMaster }
    [pscustomobject]@{ Parametr = 'Domain Naming Master';         Wartosc = $forest.DomainNamingMaster }
    [pscustomobject]@{ Parametr = 'Polityka haseł: min. długość'; Wartosc = $pp.MinPasswordLength }
    [pscustomobject]@{ Parametr = 'Polityka haseł: złożoność';    Wartosc = $pp.ComplexityEnabled }
    [pscustomobject]@{ Parametr = 'Polityka haseł: max. wiek';    Wartosc = "$($pp.MaxPasswordAge.Days) dni" }
    [pscustomobject]@{ Parametr = 'Polityka haseł: historia';     Wartosc = $pp.PasswordHistoryCount }
    [pscustomobject]@{ Parametr = 'Blokada konta: próg';          Wartosc = $pp.LockoutThreshold }
)
$invDCs = @($dcs | ForEach-Object {
    [pscustomobject]@{ DC = $_.HostName; System = $_.OperatingSystem; Lokacja = $_.Site; IP = $_.IPv4Address
                       GlobalCatalog = $_.IsGlobalCatalog; RODC = $_.IsReadOnly }
})
$invTrusts = @($trusts | ForEach-Object {
    [pscustomobject]@{ Cel = $_.Target; Kierunek = "$($_.Direction)"; Typ = "$($_.TrustType)"
                       Przechodnia = $_.ForestTransitive; WewnatrzLasu = $_.IntraForest; FiltrowanieSID = $_.SIDFilteringQuarantined }
})
#endregion

#region ---------- wynik: pliki ----------
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$base = Join-Path $OutDir ('AD_{0}_{1}_{2:yyyyMMdd-HHmm}' -f $Klient, $domain.DNSRoot, $now)

[ordered]@{ Meta = $meta; Podsumowanie = $summary; Porownanie = $diff; Znaleziska = $sorted
            Inwentaryzacja = [ordered]@{ Domena = $invDomain; DC = $invDCs; GrupyUprzywilejowane = @($invPriv); Zaufania = $invTrusts; Systemy = @($invOs) } } |
    ConvertTo-Json -Depth 6 | Set-Content "$base.json" -Encoding $encOut

$sorted | Select-Object Id, Category, Severity, Title, Count, Recommendation, Mitre |
    Export-Csv "$base.csv" -NoTypeInformation -Encoding $encOut -Delimiter ';'

$objRows = foreach ($f in $sorted) {
    foreach ($o in $f.Objects) {
        $p = @($o.PSObject.Properties)
        [pscustomobject]@{
            Znalezisko = $f.Id
            Waga       = $f.Severity
            Obiekt     = $p[0].Value
            Szczegoly  = ($p | Select-Object -Skip 1 | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '; '
        }
    }
}
if ($objRows) { @($objRows) | Export-Csv "$base`_obiekty.csv" -NoTypeInformation -Encoding $encOut -Delimiter ';' }

# --- HTML ---
function HtmlEnc([string]$s) { [System.Net.WebUtility]::HtmlEncode($s) }
function ConvertTo-HtmlTable([object[]]$Rows, [int]$Max = [int]::MaxValue) {
    $Rows = @($Rows | Where-Object { $_ })
    if ($Rows.Count -eq 0) { return '<p class="note">Brak danych.</p>' }
    $cols = @($Rows[0].PSObject.Properties.Name)
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append('<div class="tw"><table><thead><tr>')
    foreach ($c in $cols) { [void]$sb.Append("<th>$(HtmlEnc $c)</th>") }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($r in ($Rows | Select-Object -First $Max)) {
        [void]$sb.Append('<tr>')
        foreach ($c in $cols) { [void]$sb.Append("<td>$(HtmlEnc ([string]$r.$c))</td>") }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div>')
    if ($Rows.Count -gt $Max) { [void]$sb.Append("<p class=`"note`">Pokazano $Max z $($Rows.Count) obiektów - pełna lista w pliku _obiekty.csv.</p>") }
    $sb.ToString()
}
function Badge([string]$s) { "<span class=`"b $($s.ToLower())`">$s</span>" }

$css = @'
<style>
:root{--c:#b00020;--h:#e65100;--m:#f9a825;--l:#7cb342;--i:#607d8b;--n:#1f3a5f}
*{box-sizing:border-box}
body{font-family:"Segoe UI",Arial,sans-serif;font-size:13px;color:#222;margin:0;background:#f4f6f9}
.wrap{max-width:1200px;margin:0 auto;padding:24px}
header{background:var(--n);color:#fff;padding:24px;border-radius:8px}
header h1{margin:0 0 6px;font-size:22px}
header p{margin:2px 0;opacity:.9}
.conf{margin-top:10px;font-size:12px;background:rgba(255,255,255,.12);padding:6px 10px;border-radius:4px;display:inline-block}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin:18px 0}
.card{background:#fff;border-radius:8px;padding:14px 18px;flex:1;min-width:140px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.card .v{font-size:28px;font-weight:700}
.card .k{color:#666;font-size:12px}
section{background:#fff;border-radius:8px;padding:18px 20px;margin:16px 0;box-shadow:0 1px 3px rgba(0,0,0,.08)}
h2{color:var(--n);margin-top:0;font-size:18px}
h3{margin:0 0 6px;font-size:15px}
.tw{overflow-x:auto}
table{border-collapse:collapse;width:100%;margin:8px 0}
th,td{border:1px solid #dde2ea;padding:5px 8px;text-align:left;vertical-align:top}
th{background:#eef2f7;color:#1f3a5f;font-weight:600}
tr:nth-child(even) td{background:#fafbfc}
.b{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700;color:#fff}
.b.critical{background:var(--c)}.b.high{background:var(--h)}.b.medium{background:var(--m);color:#222}.b.low{background:var(--l)}.b.info{background:var(--i)}
.f{border-left:5px solid #ccc}
.f.critical{border-color:var(--c)}.f.high{border-color:var(--h)}.f.medium{border-color:var(--m)}.f.low{border-color:var(--l)}.f.info{border-color:var(--i)}
.meta{color:#666;font-size:12px;margin-bottom:10px}
.lbl{font-weight:600;color:var(--n);margin:10px 0 2px}
pre{background:#1e1e1e;color:#e6e6e6;padding:10px;border-radius:6px;overflow-x:auto;font-size:12px}
.note{color:#666;font-size:12px}
a{color:var(--n)}
button{background:var(--n);color:#fff;border:0;padding:6px 12px;border-radius:4px;cursor:pointer}
@media print{body{background:#fff}section,.card{box-shadow:none;border:1px solid #ddd}button{display:none}section{break-inside:avoid-page}}
</style>
<script>
function toggleAll(o){document.querySelectorAll('details').forEach(d=>d.open=o)}
window.addEventListener('beforeprint',()=>toggleAll(true));
</script>
'@

$sb = [System.Text.StringBuilder]::new()
[void]$sb.Append("<div class=`"wrap`"><header><h1>Przegląd bezpieczeństwa Active Directory</h1>")
[void]$sb.Append("<p><b>Klient:</b> $(HtmlEnc $Klient) &nbsp;|&nbsp; <b>Domena:</b> $(HtmlEnc $domain.DNSRoot) &nbsp;|&nbsp; <b>Data:</b> $($now.ToString('dd.MM.yyyy HH:mm'))</p>")
[void]$sb.Append("<p><b>Wykonał:</b> $(HtmlEnc $meta.Uruchomil) ze stacji $(HtmlEnc $env:COMPUTERNAME) &nbsp;|&nbsp; <b>Testy DC:</b> $(HtmlEnc $dcMethod) &nbsp;|&nbsp; PEPIX AD-Check $Version</p>")
[void]$sb.Append('<div class="conf">DOKUMENT POUFNY - zawiera informacje o podatnościach infrastruktury klienta</div></header>')

[void]$sb.Append('<div class="cards">')
[void]$sb.Append("<div class=`"card`"><div class=`"v`">$score</div><div class=`"k`">Wynik (im mniej, tym lepiej)</div></div>")
foreach ($s in 'Critical','High','Medium','Low') {
    [void]$sb.Append("<div class=`"card`"><div class=`"v`">$($sevCount[$s])</div><div class=`"k`">$(Badge $s)</div></div>")
}
if ($diff) {
    $delta = $score - [int]$diff.PoprzedniWynik
    $sign  = if ($delta -gt 0) { "+$delta" } else { "$delta" }
    $pd    = "$($diff.PoprzedniaData)"
    if ($pd.Length -ge 10) { $pd = $pd.Substring(0, 10) }
    [void]$sb.Append("<div class=`"card`"><div class=`"v`">$sign</div><div class=`"k`">Zmiana od $(HtmlEnc $pd) (było $($diff.PoprzedniWynik))</div></div>")
}
[void]$sb.Append('</div>')

if ($diff) {
    [void]$sb.Append('<section><h2>Porównanie z poprzednim przeglądem</h2>')
    [void]$sb.Append("<p><b>Nowe znaleziska:</b> $(HtmlEnc (($diff.Nowe) -join ', '))</p><p><b>Usunięte (naprawione):</b> $(HtmlEnc (($diff.Usuniete) -join ', '))</p></section>")
}

[void]$sb.Append('<section><h2>Podsumowanie według kategorii</h2>')
[void]$sb.Append((ConvertTo-HtmlTable $summary))
[void]$sb.Append('</section>')

[void]$sb.Append('<section><h2>Lista znalezisk</h2><div class="tw"><table><thead><tr><th>Waga</th><th>Znalezisko</th><th>Kategoria</th><th>Obiekty</th><th>MITRE ATT&amp;CK</th></tr></thead><tbody>')
foreach ($f in $real) {
    [void]$sb.Append("<tr><td>$(Badge $f.Severity)</td><td><a href=`"#$(HtmlEnc $f.Id)`">$(HtmlEnc $f.Title)</a></td><td>$(HtmlEnc $f.Category)</td><td>$($f.Count)</td><td>$(HtmlEnc $f.Mitre)</td></tr>")
}
[void]$sb.Append('</tbody></table></div></section>')

[void]$sb.Append('<section><h2>Szczegóły znalezisk</h2><p><button onclick="toggleAll(true)">Rozwiń wszystkie</button> <button onclick="toggleAll(false)">Zwiń wszystkie</button></p></section>')
foreach ($f in $sorted) {
    $sev = $f.Severity.ToLower()
    [void]$sb.Append("<section class=`"f $sev`" id=`"$(HtmlEnc $f.Id)`"><h3>$(Badge $f.Severity) $(HtmlEnc $f.Title)</h3>")
    $mitre = if ($f.Mitre) { " &nbsp;|&nbsp; MITRE ATT&amp;CK: $(HtmlEnc $f.Mitre)" } else { '' }
    [void]$sb.Append("<div class=`"meta`">$(HtmlEnc $f.Category) &nbsp;|&nbsp; ID: $(HtmlEnc $f.Id) &nbsp;|&nbsp; Punkty: $($weights[$f.Severity])$mitre</div>")
    if ($f.Description)    { [void]$sb.Append("<div class=`"lbl`">Ryzyko</div><div>$(HtmlEnc $f.Description)</div>") }
    if ($f.Recommendation) { [void]$sb.Append("<div class=`"lbl`">Zalecenie</div><div>$(HtmlEnc $f.Recommendation)</div>") }
    if ($f.Fix)            { [void]$sb.Append("<div class=`"lbl`">Przykładowa naprawa (do weryfikacji przed wykonaniem)</div><pre>$(HtmlEnc $f.Fix)</pre>") }
    if ($f.Count -gt 0) {
        $open = if ($f.Count -le 20) { ' open' } else { '' }
        [void]$sb.Append("<details$open><summary class=`"lbl`">Obiekty ($($f.Count))</summary>")
        [void]$sb.Append((ConvertTo-HtmlTable $f.Objects $MaxRows))
        [void]$sb.Append('</details>')
    }
    [void]$sb.Append('</section>')
}

[void]$sb.Append('<section><h2>Załącznik A. Inwentaryzacja domeny</h2>')
[void]$sb.Append('<div class="lbl">Domena i polityki</div>'); [void]$sb.Append((ConvertTo-HtmlTable $invDomain))
[void]$sb.Append('<div class="lbl">Kontrolery domeny</div>'); [void]$sb.Append((ConvertTo-HtmlTable $invDCs))
[void]$sb.Append('<div class="lbl">Członkowie grup uprzywilejowanych (rekursywnie)</div>'); [void]$sb.Append((ConvertTo-HtmlTable @($invPriv)))
[void]$sb.Append('<div class="lbl">Relacje zaufania</div>'); [void]$sb.Append((ConvertTo-HtmlTable $invTrusts))
[void]$sb.Append("<div class=`"lbl`">Systemy operacyjne (aktywne konta komputerów; AktywneOstatnio = logowanie w ciągu $StaleDays dni)</div>"); [void]$sb.Append((ConvertTo-HtmlTable @($invOs)))
[void]$sb.Append('</section>')

[void]$sb.Append('<section><h2>Załącznik B. Metodyka i ograniczenia</h2><p>')
[void]$sb.Append('Przegląd wykonano narzędziem PEPIX AD-Check na podstawie odczytu katalogu Active Directory (LDAP), metadanych replikacji, ustawień zasad grupy z SYSVOL oraz nieinwazyjnych testów sieciowych kontrolerów domeny (porty usług, udziały, czas NTP, rekordy DNS). ')
[void]$sb.Append('Konfigurację DC porównano z wybranymi kontrolami CIS Microsoft Windows Server Benchmark (profil L1, kontroler domeny) - nie jest to pełna ocena zgodności z CIS. ')
[void]$sb.Append('Przegląd nie obejmuje testów penetracyjnych, analizy uprawnień (ACL) na obiektach AD i GPO, usług certyfikatów (ADCS) ani stacji końcowych. ')
[void]$sb.Append("Wersje systemów ustalono z atrybutów operatingSystem/operatingSystemVersion kont komputerów (bez łączenia się z komputerami); daty końca wsparcia według Microsoft Lifecycle, stan na $osLifecycleAsOf. ")
[void]$sb.Append("Za nieaktywne uznano konta bez logowania od $StaleDays dni (atrybut lastLogonTimestamp, dokładność do ok. 14 dni). ")
[void]$sb.Append('Wartości odczytane z GPO opisują konfigurację zamierzoną; ustawienia lokalne na DC mogą się od niej różnić. Polecenia naprawcze są przykładowe i wymagają weryfikacji oraz zgłoszenia zmiany przed wykonaniem.')
[void]$sb.Append('</p></section></div>')

ConvertTo-Html -Head $css -Title "AD $Klient $($now.ToString('yyyy-MM-dd'))" -Body $sb.ToString() | Set-Content "$base.html" -Encoding $encOut
#endregion

Write-Host "`nKlient: $Klient | Domena: $($domain.DNSRoot) | Wynik: $score | Testy DC: $dcMethod" -ForegroundColor Cyan
$real | Format-Table Severity, Category, Title -AutoSize
Write-Host "Raport: $base.html" -ForegroundColor Green
Write-Host "Dane:   $base.json | $base.csv | $base`_obiekty.csv" -ForegroundColor Green
