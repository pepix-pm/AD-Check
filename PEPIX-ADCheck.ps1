<#
.SYNOPSIS
    PEPIX AD-Check — przegląd bezpieczeństwa Active Directory (wersja 0.2)

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

# Bez #Requires i z ręcznym ustaleniem OutDir - skrypt musi działać także jako scriptblock (iex z GitHuba),
# gdzie #Requires nie jest obsługiwane, a $PSScriptRoot jest pusty.
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -lt 5) { throw 'Wymagany Windows PowerShell 5.1 lub nowszy.' }
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    throw 'Brak modułu ActiveDirectory (RSAT). Serwer: Install-WindowsFeature RSAT-AD-PowerShell; Windows 10/11: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'
}
Import-Module ActiveDirectory
if (-not $OutDir) {
    # z pliku: obok skryptu; z iex: profil użytkownika (nie bieżący katalog - w sesji admina to często System32)
    $OutDir = if ($PSScriptRoot) { Join-Path $PSScriptRoot 'raporty' } else { Join-Path $env:USERPROFILE 'PEPIX-ADCheck\raporty' }
}
$Version = '0.3'

$now      = Get-Date
$staleDt  = $now.AddDays(-$StaleDays)
$domain   = Get-ADDomain -Server $Server
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
Invoke-Check 'COMPUTERS' {
    $lapsAttrs = @((Get-ADObject -SearchBase $rootDse.schemaNamingContext -Server $Server `
        -LDAPFilter '(|(lDAPDisplayName=ms-Mcs-AdmPwdExpirationTime)(lDAPDisplayName=msLAPS-PasswordExpirationTime))' `
        -Properties lDAPDisplayName).lDAPDisplayName)

    $props = @('OperatingSystem','LastLogonDate','TrustedForDelegation','primaryGroupID','whenCreated') + $lapsAttrs
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
    Add-IfAny @{
        Id = 'C-OS-EOL'; Category = $catComp; Severity = 'High'
        Title = 'Aktywne komputery z systemem bez wsparcia'
        Objects = ($comps | Where-Object { $_.OperatingSystem -match 'XP|Vista|Windows 7|Windows 8|2000|2003|2008|2012' } |
                   ForEach-Object { ConvertTo-ComputerRow $_ })
        Description = 'Systemy bez poprawek bezpieczeństwa; znane podatności pozostają otwarte na stałe.'
        Recommendation = 'Zaplanować wymianę lub aktualizację; do tego czasu izolacja sieciowa i ograniczenie logowania kont uprzywilejowanych.'
        Fix = (Fx '# brak poprawki skryptem - migracja systemu / wymiana sprzętu')
        Mitre = 'T1210'
    }
    Add-IfAny @{
        Id = 'C-OS-W10'; Category = $catComp; Severity = 'Medium'
        Title = 'Komputery z Windows 10 (koniec wsparcia: październik 2025)'
        Objects = ($comps | Where-Object { $_.OperatingSystem -match 'Windows 10' } | ForEach-Object { ConvertTo-ComputerRow $_ })
        Description = 'Windows 10 nie otrzymuje poprawek bez płatnej subskrypcji ESU.'
        Recommendation = 'Migracja do Windows 11 lub potwierdzona subskrypcja ESU; zweryfikować zgodność sprzętu.'
        Fix = (Fx '# brak poprawki skryptem - migracja do Windows 11')
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
        Add-IfAny @{
            Id = 'C-LAPS-MISSING'; Category = $catComp; Severity = 'Medium'
            Title = 'Komputery bez hasła zarządzanego przez LAPS'
            Objects = ($nonDc | Where-Object { $c = $_; -not ($lapsAttrs | Where-Object { $c.$_ }) } | ForEach-Object { ConvertTo-ComputerRow $_ })
            Description = 'Te komputery nie mają hasła lokalnego administratora zarządzanego przez LAPS.'
            Recommendation = 'Sprawdzić, czy OU są objęte GPO LAPS i czy komputery mają uprawnienie do zapisu hasła.'
            Fix = (Fx 'Set-LapsADComputerSelfPermission -Identity ''<DN OU>''', 'gpresult /r   # na komputerze: czy GPO LAPS jest zastosowane')
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
        Objects = ($dcs | Where-Object { $_.OperatingSystem -match '2003|2008|2012' } |
                   ForEach-Object { [pscustomobject]@{ DC = $_.HostName; System = $_.OperatingSystem; Lokacja = $_.Site } })
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
            Inwentaryzacja = [ordered]@{ Domena = $invDomain; DC = $invDCs; GrupyUprzywilejowane = @($invPriv); Zaufania = $invTrusts } } |
    ConvertTo-Json -Depth 6 | Set-Content "$base.json" -Encoding UTF8

$sorted | Select-Object Id, Category, Severity, Title, Count, Recommendation, Mitre |
    Export-Csv "$base.csv" -NoTypeInformation -Encoding UTF8 -Delimiter ';'

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
if ($objRows) { @($objRows) | Export-Csv "$base`_obiekty.csv" -NoTypeInformation -Encoding UTF8 -Delimiter ';' }

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
[void]$sb.Append('</section>')

[void]$sb.Append('<section><h2>Załącznik B. Metodyka i ograniczenia</h2><p>')
[void]$sb.Append('Przegląd wykonano narzędziem PEPIX AD-Check na podstawie odczytu katalogu Active Directory (LDAP), ustawień zasad grupy z SYSVOL oraz nieinwazyjnych testów sieciowych kontrolerów domeny. ')
[void]$sb.Append('Przegląd nie obejmuje testów penetracyjnych, analizy uprawnień (ACL) na obiektach AD i GPO, usług certyfikatów (ADCS) ani stacji końcowych. ')
[void]$sb.Append("Za nieaktywne uznano konta bez logowania od $StaleDays dni (atrybut lastLogonTimestamp, dokładność do ok. 14 dni). ")
[void]$sb.Append('Wartości odczytane z GPO opisują konfigurację zamierzoną; ustawienia lokalne na DC mogą się od niej różnić. Polecenia naprawcze są przykładowe i wymagają weryfikacji oraz zgłoszenia zmiany przed wykonaniem.')
[void]$sb.Append('</p></section></div>')

ConvertTo-Html -Head $css -Title "AD $Klient $($now.ToString('yyyy-MM-dd'))" -Body $sb.ToString() | Set-Content "$base.html" -Encoding UTF8
#endregion

Write-Host "`nKlient: $Klient | Domena: $($domain.DNSRoot) | Wynik: $score | Testy DC: $dcMethod" -ForegroundColor Cyan
$real | Format-Table Severity, Category, Title -AutoSize
Write-Host "Raport: $base.html" -ForegroundColor Green
Write-Host "Dane:   $base.json | $base.csv | $base`_obiekty.csv" -ForegroundColor Green
