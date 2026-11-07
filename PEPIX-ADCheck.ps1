<#
.SYNOPSIS
    PEPIX AD-Check — przegląd bezpieczeństwa Active Directory (wersja 0.15)

.DESCRIPTION
    Uruchamiać ze stacji w domenie klienta. Nie wymaga RSAT: AD odczytywane przez LDAP (System.DirectoryServices).
    Domyślnie WYSTARCZY ZWYKŁE KONTO DOMENOWE:
      - dane katalogowe: zapytania LDAP,
      - Print Spooler na DC: test potoku \\DC\pipe\spoolss,
      - SMBv1 na DC: sonda negocjacji SMB1 na TCP 445,
      - podpisywanie LDAP, channel binding, poziom NTLM: odczyt GPO z SYSVOL (GptTmpl.inf).
    -UseWinRM: zamiast GPO i sond odczyt rzeczywistych wartości z rejestru DC (wymaga admina na DC).
    Wynik: szczegółowy raport HTML, JSON (do porównań), CSV znalezisk i CSV obiektów.
    Punkty: Critical=25, High=10, Medium=3, Low=1 za znalezisko; wynik 0-100 w czterech obszarach ryzyka,
    wynik ogólny = najgorszy obszar, poziom dojrzałości 1-5; im mniej punktów, tym lepiej.

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
$Version = '0.19'

#region ---------- wymagania ----------
# Sprawdzane ręcznie zamiast #Requires: skrypt bywa uruchamiany jako scriptblock (z GitHuba), gdzie #Requires nie działa.
# Wszystkie braki zbierane naraz, żeby nie poprawiać ich pojedynczo.
$braki = [System.Collections.Generic.List[string]]::new()

if ([System.Environment]::OSVersion.Platform -ne 'Win32NT') {
    $braki.Add('System inny niż Windows - odczyt AD (System.DirectoryServices), SYSVOL i testy DC wymagają Windows.')
}
if (-not $Server) {
    $braki.Add('Nie ustalono domeny: stacja/konto poza domeną. Podaj -Server <domena lub DC>.')
}
if ($Previous -and -not (Test-Path -LiteralPath $Previous -PathType Leaf)) {
    $braki.Add("Nie znaleziono pliku -Previous: $Previous")
}

if ($braki.Count -eq 0) {
    # Odczyt AD przez LDAP (System.DirectoryServices, wbudowane w Windows) - bez modułu RSAT ActiveDirectory
    try {
        $rde = New-Object System.DirectoryServices.DirectoryEntry ("LDAP://$Server/RootDSE")
        $rootDse = [pscustomobject]@{
            defaultNamingContext       = [string]$rde.Properties['defaultNamingContext'].Value
            configurationNamingContext = [string]$rde.Properties['configurationNamingContext'].Value
            schemaNamingContext        = [string]$rde.Properties['schemaNamingContext'].Value
            rootDomainNamingContext    = [string]$rde.Properties['rootDomainNamingContext'].Value
            dnsHostName                = [string]$rde.Properties['dnsHostName'].Value
        }
        $rde.psbase.Dispose()
        if (-not $rootDse.defaultNamingContext) { throw 'pusta odpowiedź RootDSE' }
    } catch {
        $braki.Add("Brak połączenia LDAP z domeną ($Server): $($_.Exception.Message). Wymagany dostęp do kontrolera domeny (TCP 389) i DNS domeny.")
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

#region ---------- dostęp do AD przez LDAP ----------
# System.DirectoryServices zamiast modułu ActiveDirectory: działa na każdym Windows bez RSAT i bez uprawnień admina na stacji.
# Obiekty dostają te same nazwy właściwości co z modułu AD (SID, Enabled, PasswordLastSet, LastLogonDate, ...),
# a atrybuty LDAP są dostępne pod własnymi nazwami (wielkość liter bez znaczenia).
$LdapServer = $Server
$domainDn   = $rootDse.defaultNamingContext
$ldapMulti  = @('serviceprincipalname', 'memberof', 'sidhistory', 'objectclass', 'member', 'serverreferencebl',
                'msds-ncreplinboundneighbors', 'msds-replattributemetadata', 'msds-enabledfeaturebl')

function ConvertTo-LdapFilterValue([string]$Value) {
    $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29')
}
function ConvertFrom-DnToDns([string]$Dn) {
    (($Dn -split ',') | Where-Object { $_ -match '^DC=' } | ForEach-Object { $_.Substring(3) }) -join '.'
}
function ConvertFrom-LdapTime([string]$Text) {
    if (-not $Text) { return $null }
    $t = [datetimeoffset]::Parse($Text, [System.Globalization.CultureInfo]::InvariantCulture).LocalDateTime
    if ($t.Year -le 1601) { $null } else { $t }
}

# Wynik wyszukiwania LDAP (ResultPropertyCollection lub hashtable w testach) -> obiekt jak z modułu AD
function ConvertFrom-LdapResult($P) {
    $names = if ($P -is [System.Collections.IDictionary]) { @($P.Keys) } else { @($P.PropertyNames) }
    $o = [ordered]@{}
    foreach ($n in $names) {
        $k = "$n".ToLower()
        if ($k -eq 'adspath') { continue }
        $v = @($P[$n])
        if ($ldapMulti -contains $k) { $o[$k] = $v } else { $o[$k] = $v[0] }
    }
    if ($o.Contains('objectclass')) { $o['objectclass'] = "$(@($o['objectclass'])[-1])" }   # najbardziej szczegółowa klasa
    if ($o.Contains('objectsid'))   { $o['SID'] = [System.Security.Principal.SecurityIdentifier]::new([byte[]]$o['objectsid'], 0) }
    if ($o.Contains('sidhistory'))  { $o['sidhistory'] = @($o['sidhistory'] | ForEach-Object { [System.Security.Principal.SecurityIdentifier]::new([byte[]]$_, 0) }) }
    if ($o.Contains('useraccountcontrol')) {
        $u = [int]$o['useraccountcontrol']
        $o['Enabled']               = -not ($u -band 0x2)
        $o['PasswordNeverExpires']  = [bool]($u -band 0x10000)
        $o['DoesNotRequirePreAuth'] = [bool]($u -band 0x400000)
        $o['TrustedForDelegation']  = [bool]($u -band 0x80000)
        $o['AccountNotDelegated']   = [bool]($u -band 0x100000)
    }
    $o['PasswordLastSet'] = $(if ([int64]$o['pwdlastset'] -gt 0) { [datetime]::FromFileTime([int64]$o['pwdlastset']) } else { $null })
    $o['LastLogonDate']   = $(if ([int64]$o['lastlogontimestamp'] -gt 0) { [datetime]::FromFileTime([int64]$o['lastlogontimestamp']) } else { $null })
    if ($o.Contains('ntsecuritydescriptor') -and $o['ntsecuritydescriptor'] -is [byte[]]) {
        $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
        $sd.SetSecurityDescriptorBinaryForm([byte[]]$o['ntsecuritydescriptor'])
        $o['ntsecuritydescriptor'] = $sd
    }
    [pscustomobject]$o
}

# Wyszukiwanie LDAP; zawsze pobiera podstawowe atrybuty kont (DN, nazwy, UAC, SID, daty haseł i logowania)
function Find-Ldap {
    param(
        [string]$Filter = '(objectClass=*)',
        [string]$SearchBase,
        [ValidateSet('Base', 'OneLevel', 'Subtree')][string]$Scope = 'Subtree',
        [string[]]$Properties = @(),
        [string]$Server = $LdapServer,
        [switch]$SecurityDescriptor
    )
    if (-not $SearchBase) { $SearchBase = $domainDn }
    $root = New-Object System.DirectoryServices.DirectoryEntry ("LDAP://$Server/" + ($SearchBase -replace '/', '\/'))
    $s = New-Object System.DirectoryServices.DirectorySearcher -ArgumentList $root, $Filter
    $s.SearchScope = [System.DirectoryServices.SearchScope]$Scope
    if ($Scope -ne 'Base') { $s.PageSize = 1000 }
    $load = @('distinguishedName', 'name', 'objectClass', 'sAMAccountName', 'userAccountControl', 'objectSid',
              'pwdLastSet', 'lastLogonTimestamp', 'whenCreated') + $Properties
    foreach ($p in @($load | Where-Object { $_ } | Sort-Object -Unique)) { [void]$s.PropertiesToLoad.Add($p) }
    if ($SecurityDescriptor) { $s.SecurityMasks = [System.DirectoryServices.SecurityMasks]'Dacl,Owner,Group' }
    $res = $null
    try {
        $res = $s.FindAll()
        foreach ($r in $res) { ConvertFrom-LdapResult $r.Properties }
    } finally {
        if ($res) { $res.Dispose() }
        $s.Dispose()
        try { $root.psbase.Dispose() } catch { $null = $_ }   # psbase: adapter DirectoryEntry traktuje metody jak atrybuty LDAP
    }
}

# Pojedynczy obiekt: po SID (S-1-...), DN (zawiera '=') albo sAMAccountName
function Get-LdapObject {
    param(
        [Parameter(Mandatory)][string]$Identity,
        [string[]]$Properties = @(),
        [string]$Server = $LdapServer,
        [switch]$SecurityDescriptor
    )
    $r = if ($Identity -match '^S-1-\d') { Find-Ldap -Filter "(objectSid=$Identity)" -Properties $Properties -Server $Server -SecurityDescriptor:$SecurityDescriptor }
         elseif ($Identity -notmatch '=') { Find-Ldap -Filter "(sAMAccountName=$(ConvertTo-LdapFilterValue $Identity))" -Properties $Properties -Server $Server -SecurityDescriptor:$SecurityDescriptor }
         else { Find-Ldap -SearchBase $Identity -Scope Base -Properties $Properties -Server $Server -SecurityDescriptor:$SecurityDescriptor }
    @($r)[0]
}

# Użytkownicy w grupie (rekursywnie, LDAP_MATCHING_RULE_IN_CHAIN); bez członkostwa przez primaryGroupID
function Get-LdapGroupUsers([string]$GroupSid, [string[]]$Properties = @()) {
    $g = Get-LdapObject -Identity $GroupSid
    if (-not $g) { throw "nie znaleziono grupy $GroupSid" }
    Find-Ldap -Properties $Properties -Filter ("(&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=" + (ConvertTo-LdapFilterValue $g.distinguishedName) + '))')
}

# DN właściciela roli FSMO (NTDS Settings) -> nazwa DNS serwera; usunięty DC zostaje jako DN
function Get-FsmoHost([string]$OwnerDn) {
    if (-not $OwnerDn) { return $null }
    if ($OwnerDn -match 'DEL:') { return $OwnerDn }
    $srv = Get-LdapObject -Identity (($OwnerDn -split '(?<!\\),', 2)[1]) -Properties dNSHostName
    if ($srv.dnshostname) { $srv.dnshostname } else { $OwnerDn }
}

$modeName = @{ 0 = 'Windows2000'; 1 = 'Windows2003Interim'; 2 = 'Windows2003'; 3 = 'Windows2008'; 4 = 'Windows2008R2'
               5 = 'Windows2012'; 6 = 'Windows2012R2'; 7 = 'Windows2016'; 10 = 'Windows2025' }
$configDn = $rootDse.configurationNamingContext

$dObj = Get-LdapObject -Identity $domainDn -Properties 'msDS-Behavior-Version', fSMORoleOwner, minPwdLength, pwdProperties,
        maxPwdAge, pwdHistoryLength, lockoutThreshold, 'ms-DS-MachineAccountQuota'
$xref = @(Find-Ldap -SearchBase "CN=Partitions,$configDn" -Properties nETBIOSName -Filter "(&(objectClass=crossRef)(nCName=$(ConvertTo-LdapFilterValue $domainDn)))")[0]
$domain = [pscustomobject]@{
    DNSRoot                    = ConvertFrom-DnToDns $domainDn
    NetBIOSName                = $xref.netbiosname
    DistinguishedName          = $domainDn
    DomainSID                  = $dObj.SID
    DomainMode                 = "$($modeName[[int]$dObj.'msds-behavior-version'])Domain"
    PDCEmulator                = Get-FsmoHost $dObj.fsmoroleowner
    RIDMaster                  = Get-FsmoHost (Get-LdapObject -Identity "CN=RID Manager`$,CN=System,$domainDn" -Properties fSMORoleOwner).fsmoroleowner
    InfrastructureMaster       = Get-FsmoHost (Get-LdapObject -Identity "CN=Infrastructure,$domainDn" -Properties fSMORoleOwner).fsmoroleowner
    DomainControllersContainer = "OU=Domain Controllers,$domainDn"
}
$part = Get-LdapObject -Identity "CN=Partitions,$configDn" -Properties 'msDS-Behavior-Version', fSMORoleOwner
$forest = [pscustomobject]@{
    Name               = ConvertFrom-DnToDns $rootDse.rootDomainNamingContext
    RootDomain         = ConvertFrom-DnToDns $rootDse.rootDomainNamingContext
    ForestMode         = "$($modeName[[int]$part.'msds-behavior-version'])Forest"
    SchemaMaster       = Get-FsmoHost (Get-LdapObject -Identity $rootDse.schemaNamingContext -Properties fSMORoleOwner).fsmoroleowner
    DomainNamingMaster = Get-FsmoHost $part.fsmoroleowner
}
$dSid = $domain.DomainSID.Value

# Kontrolery domeny: konta komputerów z primaryGroupID 516 (DC) / 521 (RODC); lokacja i GC z obiektu serwera w CN=Sites
function Get-LdapDomainControllers {
    foreach ($c in @(Find-Ldap -Filter '(&(objectCategory=computer)(|(primaryGroupID=516)(primaryGroupID=521)))' -Properties dNSHostName, operatingSystem, operatingSystemVersion, primaryGroupID, serverReferenceBL)) {
        $srvDn = @($c.serverreferencebl | Where-Object { $_ -like "*,CN=Sites,$configDn" })[0]
        $site = if ($srvDn) { (($srvDn -split '(?<!\\),')[2]) -replace '^CN=', '' } else { '' }
        $gc = $false
        if ($srvDn) { try { $gc = [bool]([int](Get-LdapObject -Identity "CN=NTDS Settings,$srvDn" -Properties options).options -band 1) } catch { $gc = $false } }
        $ip = ''
        try { $ip = "$(@([System.Net.Dns]::GetHostAddresses($c.dnshostname) | Where-Object AddressFamily -eq 'InterNetwork')[0])" } catch { $ip = '' }
        [pscustomobject]@{
            Name = $c.name; HostName = $c.dnshostname; OperatingSystem = $c.operatingsystem; OperatingSystemVersion = $c.operatingsystemversion
            Site = $site; IPv4Address = $ip; IsGlobalCatalog = $gc; IsReadOnly = ([int]$c.primarygroupid -eq 521); ComputerObjectDN = $c.distinguishedname
        }
    }
}

# Polityka haseł domeny (atrybuty obiektu domeny)
function Get-LdapPasswordPolicy {
    $age = [int64]$dObj.maxpwdage
    [pscustomobject]@{
        MinPasswordLength    = [int]$dObj.minpwdlength
        ComplexityEnabled    = [bool]([int]$dObj.pwdproperties -band 1)
        MaxPasswordAge       = $(if ($age -eq 0 -or $age -eq [int64]::MinValue) { [TimeSpan]::Zero } else { [TimeSpan]::FromTicks(-$age) })
        PasswordHistoryCount = [int]$dObj.pwdhistorylength
        LockoutThreshold     = [int]$dObj.lockoutthreshold
    }
}

# Relacje zaufania (obiekty trustedDomain w CN=System)
function Get-LdapTrusts {
    $dir  = @{ 0 = 'Disabled'; 1 = 'Inbound'; 2 = 'Outbound'; 3 = 'BiDirectional' }
    $type = @{ 1 = 'Downlevel'; 2 = 'Uplevel'; 3 = 'MIT'; 4 = 'DCE' }
    foreach ($t in @(Find-Ldap -SearchBase "CN=System,$domainDn" -Filter '(objectClass=trustedDomain)' -Properties trustPartner, trustDirection, trustType, trustAttributes, 'msDS-SupportedEncryptionTypes')) {
        $a = [int]$t.trustattributes
        [pscustomobject]@{
            Target = $t.trustpartner; Direction = $dir[[int]$t.trustdirection]; TrustType = $type[[int]$t.trusttype]
            ForestTransitive = [bool]($a -band 0x8); IntraForest = [bool]($a -band 0x20); SIDFilteringQuarantined = [bool]($a -band 0x4)
        }
    }
}

# Partnerzy replikacji przychodzącej DC (atrybut konstruowany msDS-NCReplInboundNeighbors, XML) - jak Get-ADReplicationPartnerMetadata
function Get-LdapReplPartners([string]$Dc) {
    $rde = New-Object System.DirectoryServices.DirectoryEntry ("LDAP://$Dc/RootDSE")
    $ncs = @($rde.Properties['namingContexts'] | ForEach-Object { "$_" })
    $rde.psbase.Dispose()
    foreach ($nc in $ncs) {
        $o = Get-LdapObject -Identity $nc -Server $Dc -Properties 'msDS-NCReplInboundNeighbors'
        foreach ($x in @($o.'msds-ncreplinboundneighbors' | Where-Object { $_ })) {
            $n = ([xml]$x).DS_REPL_NEIGHBOR
            [pscustomobject]@{
                Server = $Dc; Partner = $n.pszSourceDsaDN; Partition = $n.pszNamingContext
                LastReplicationSuccess = ConvertFrom-LdapTime $n.ftimeLastSyncSuccess
                LastReplicationAttempt = ConvertFrom-LdapTime $n.ftimeLastSyncAttempt
                LastReplicationResult  = [int]$n.dwLastSyncResult
                ConsecutiveReplicationFailureCount = [int]$n.cNumConsecutiveSyncFailures
            }
        }
    }
}

# Metadane replikacji atrybutu (msDS-ReplAttributeMetaData, XML) - data ostatniej zmiany źródłowej
function Get-LdapAttrChangeTime([string]$Dn, [string]$Attribute) {
    $o = Get-LdapObject -Identity $Dn -Properties 'msDS-ReplAttributeMetaData'
    foreach ($x in @($o.'msds-replattributemetadata' | Where-Object { $_ })) {
        $m = ([xml]$x).DS_REPL_ATTR_META_DATA
        if ($m.pszAttributeName -eq $Attribute) { return (ConvertFrom-LdapTime $m.ftimeLastOriginatingChange) }
    }
    $null
}
#endregion

$now      = Get-Date
$staleDt  = $now.AddDays(-$StaleDays)
$findings = [System.Collections.Generic.List[object]]::new()
$weights  = @{ Critical = 25; High = 10; Medium = 3; Low = 1; Info = 0 }

$catPriv = 'Konta uprzywilejowane'
$catUser = 'Konta użytkowników'
$catComp = 'Komputery'
$catDom  = 'Domena i las'
$catDC   = 'Kontrolery domeny'
$catHealth = 'Kondycja domeny i replikacja'
$catCis    = 'Konfiguracja DC (CIS L1)'
$catKrb    = 'Kerberos i szyfrowanie'

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
    26300 = @{ Nazwa = '26H2'; Ent = '2029-10-09'; Pro = '2028-10-10' }   # szacunek (24/36 mies. od jesieni 2026) - potwierdzić po GA
}
$win10Ltsc = @{
    10240 = @{ Nazwa = 'LTSB 2015'; Koniec = '2025-10-14' }
    14393 = @{ Nazwa = 'LTSB 2016'; Koniec = '2026-10-13' }
    17763 = @{ Nazwa = 'LTSC 2019'; Koniec = '2029-01-09' }
    19044 = @{ Nazwa = 'LTSC 2021'; Koniec = '2027-01-12'; IoT = '2032-01-13' }
}
$serverEol = [ordered]@{ '2025' = '2034-11-14'; '2022' = '2031-10-14'; '2019' = '2029-01-09'; '2016' = '2027-01-12'
                         '2012' = '2023-10-10'; '2008' = '2020-01-14'; '2003' = '2015-07-14' }
# Build -> wersja serwera, gdy w nazwie nie ma roku lub rok jest nietypowy ("Windows Server® 2008", "Hyper-V Server", SBS 2011)
$serverBuilds = @{ 3790 = '2003'; 6001 = '2008'; 6002 = '2008'; 6003 = '2008'; 7600 = '2008 R2'; 7601 = '2008 R2'
                   9200 = '2012'; 9600 = '2012 R2'; 14393 = '2016'; 17763 = '2019'; 20348 = '2022'; 26100 = '2025' }
$sacBuilds    = @(16299, 17134, 18362, 18363, 19041, 19042)   # Windows Server SAC 1709-20H2, wszystkie bez wsparcia od 2022-08-09
$legacyClient = [ordered]@{ 'Windows 8.1' = '2023-01-10'; 'Windows 8' = '2016-01-12'; 'Windows 7' = '2020-01-14'
                            'Vista' = '2017-04-11'; 'Windows XP' = '2014-04-08'; 'Windows 2000' = '2010-07-13'; 'Windows NT' = '2004-12-31' }

# Wersja i data końca wsparcia na podstawie atrybutów operatingSystem i operatingSystemVersion ("10.0 (22631)").
# Typ: Legacy | Serwer | LTSC | W10 | W11 | Inne (system spoza Windows lub nierozpoznany - bez oceny).
function Get-OsLifecycle([string]$Os, [string]$Ver) {
    $build = 0
    if ($Ver -match '\((\d+)\)') { $build = [int]$Matches[1] }
    $r = [pscustomobject]@{ Typ = 'Inne'; Wersja = ''; Koniec = $null }
    if ($Os -notmatch 'Windows|Hyper-V Server') { return $r }

    foreach ($k in $legacyClient.Keys) {
        if ($Os -match [regex]::Escape($k)) { $r.Typ = 'Legacy'; $r.Wersja = $k; $r.Koniec = [datetime]$legacyClient[$k]; return $r }
    }
    # Windows Server, Hyper-V Server, Storage/Web/Small Business Server; nazwa bywa z ® ("Windows Server® 2008 Standard")
    if ($Os -match 'Server') {
        $r.Typ = 'Serwer'
        $wer = $null
        if ($Os -match '(?<!\d)(20\d\d)(?!\d)' -and $serverEol.Contains($Matches[1])) {
            $y = $Matches[1]; $wer = $(if ($Os -match "$y\s*R2") { "$y R2" } else { $y })
        } elseif ($serverBuilds.ContainsKey($build)) {
            $wer = $serverBuilds[$build]
        }
        if ($wer) {
            $prefix = $(if ($Os -match 'Hyper-V Server') { 'Hyper-V ' } else { '' })
            $r.Wersja = "$prefix$wer"; $r.Koniec = [datetime]$serverEol[$wer.Substring(0, 4)]
        } elseif ($sacBuilds -contains $build) {
            $r.Wersja = "SAC (build $build)"; $r.Koniec = [datetime]'2022-08-09'
        } elseif ($build -gt 0) { $r.Wersja = "build $build" }   # nieznany build - bez oceny
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
        } elseif ($build -gt 26300) { $r.Wersja = "build $build (nowsza niż tabela / Insider)" }   # bez oceny
        else { $r.Wersja = "build $build" }
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

# ---------- katalog reguł: obszar ryzyka, model, test źródłowy ----------
# O: S = obiekty nieaktualne, P = konta uprzywilejowane, T = zaufania, A = anomalie (wynik 0-100 na obszar, wynik ogólny = najgorszy obszar)
# M: model ryzyka (wiersz macierzy); C: nazwa Invoke-Check (DC-PROBE = testy pojedynczych DC); W: wymaganie (DC = bez -SkipDCChecks, WinRM = -UseWinRM)
# N: reguła nie dotyczy, gdy wystąpi wskazane znalezisko; T: krótki opis do listy sprawdzonych reguł
# Nowy test = nowy wpis tutaj (inaczej trafi do obszaru Anomalie, modelu "Inne" i nie pojawi się na liście sprawdzonych reguł).
$areaNames = [ordered]@{ S = 'Obiekty nieaktualne'; P = 'Konta uprzywilejowane'; T = 'Zaufania'; A = 'Anomalie' }
$ruleCatalog = @(
    @{ Id = 'U-STALE';           O = 'S'; M = 'Nieaktywne konta';             C = 'USERS';        T = 'Aktywne konta użytkowników nieużywane' }
    @{ Id = 'C-STALE';           O = 'S'; M = 'Nieaktywne konta';             C = 'COMPUTERS';    T = 'Aktywne konta komputerów nieużywane' }
    @{ Id = 'U-PWDNOTREQ';       O = 'S'; M = 'Konfiguracja kont';            C = 'USERS';        T = 'Flaga PASSWD_NOTREQD' }
    @{ Id = 'U-REVERSIBLE';      O = 'S'; M = 'Konfiguracja kont';            C = 'USERS';        T = 'Hasła przechowywane odwracalnie' }
    @{ Id = 'U-PNE';             O = 'S'; M = 'Konfiguracja kont';            C = 'USERS';        T = 'Zwykłe konta z hasłem bez wygasania' }
    @{ Id = 'U-SIDHIST';         O = 'S'; M = 'Konfiguracja kont';            C = 'USERS';        T = 'Konta z SIDHistory' }
    @{ Id = 'U-GUEST';           O = 'S'; M = 'Konfiguracja kont';            C = 'USERS';        T = 'Włączone konto Gość' }
    @{ Id = 'C-MAQ';             O = 'S'; M = 'Konfiguracja kont';            C = 'COMPUTERS';    T = 'MachineAccountQuota > 0' }
    @{ Id = 'C-OS-EOL';          O = 'S'; M = 'Przestarzałe systemy';         C = 'COMPUTERS';    T = 'Komputery z systemem bez wsparcia' }
    @{ Id = 'C-OS-W10';          O = 'S'; M = 'Przestarzałe systemy';         C = 'COMPUTERS';    T = 'Windows 10 (poza LTSC)' }
    @{ Id = 'C-OS-FEATURE';      O = 'S'; M = 'Przestarzałe systemy';         C = 'COMPUTERS';    T = 'Windows 11 w wersji bez wsparcia' }
    @{ Id = 'C-OS-SOON';         O = 'S'; M = 'Przestarzałe systemy';         C = 'COMPUTERS';    T = 'Koniec wsparcia serwerów/LTSC w ciągu 12 mies.' }
    @{ Id = 'DC-OS-EOL';         O = 'S'; M = 'Przestarzałe systemy';         C = 'DC-OS';        T = 'DC z systemem bez wsparcia' }
    @{ Id = 'D-DFL';             O = 'S'; M = 'Przestarzałe systemy';         C = 'DOMAIN';       T = 'Poziom funkcjonalny domeny < 2016' }
    @{ Id = 'DC-PATCH-OLD';      O = 'S'; M = 'Zarządzanie poprawkami';       C = 'DC-PATCH';     W = 'DC'; T = 'DC bez aktualnych poprawek' }
    @{ Id = 'DC-PATCH-DIFF';     O = 'S'; M = 'Zarządzanie poprawkami';       C = 'DC-PATCH';     W = 'DC'; T = 'Różny poziom poprawek DC' }
    @{ Id = 'DC-REBOOT';         O = 'S'; M = 'Zarządzanie poprawkami';       C = 'DC-PATCH';     W = 'WinRM'; T = 'DC oczekujący na restart / długi uptime' }
    @{ Id = 'U-DES';             O = 'S'; M = 'Przestarzałe protokoły';       C = 'USERS';        T = 'Konta z wymuszonym DES' }
    @{ Id = 'D-KRB-DES';         O = 'S'; M = 'Przestarzałe protokoły';       C = 'KRB-ENC';      T = 'DES dopuszczony w konfiguracji Kerberos' }
    @{ Id = 'D-KRB-NOAES';       O = 'S'; M = 'Przestarzałe protokoły';       C = 'KRB-ENC';      T = 'Konta bez kluczy AES' }
    @{ Id = 'DC-KRB-DES-USED';   O = 'S'; M = 'Przestarzałe protokoły';       C = 'KRB-ENC';      W = 'WinRM'; T = 'Wydane bilety Kerberos DES' }
    @{ Id = 'DC-KRB-RC4-USED';   O = 'S'; M = 'Przestarzałe protokoły';       C = 'KRB-ENC';      W = 'WinRM'; T = 'Wydane bilety Kerberos RC4' }
    @{ Id = 'DC-SMB1';           O = 'S'; M = 'Przestarzałe protokoły';       C = 'DC-PROBE';     W = 'DC'; T = 'SMBv1 na DC' }
    @{ Id = 'DC-NTLMV1';         O = 'S'; M = 'Przestarzałe protokoły';       C = 'DC-PROBE';     W = 'DC'; T = 'DC akceptuje NTLMv1/LM' }
    @{ Id = 'DC-REPL-FAIL';      O = 'S'; M = 'Replikacja i kondycja';        C = 'REPL';         T = 'Błędy replikacji AD' }
    @{ Id = 'DC-REPL-STALE';     O = 'S'; M = 'Replikacja i kondycja';        C = 'REPL';         T = 'Replikacja nieudana > 24 h' }
    @{ Id = 'DC-REPL-TSL';       O = 'S'; M = 'Replikacja i kondycja';        C = 'REPL';         T = 'Replikacja nieudana > tombstone lifetime' }
    @{ Id = 'D-SINGLEDC';        O = 'S'; M = 'Replikacja i kondycja';        C = 'REPL';         T = 'Tylko jeden kontroler domeny' }
    @{ Id = 'D-SYSVOL-FRS';      O = 'S'; M = 'Replikacja i kondycja';        C = 'SYSVOL-FRS';   T = 'SYSVOL na FRS' }
    @{ Id = 'D-FSMO';            O = 'S'; M = 'Replikacja i kondycja';        C = 'FSMO';         T = 'Osierocone role FSMO' }
    @{ Id = 'DC-MACHINEPWD';     O = 'S'; M = 'Replikacja i kondycja';        C = 'DC-MACHINEPWD'; T = 'Stare hasło konta komputera DC' }
    @{ Id = 'DC-PORTS';          O = 'S'; M = 'Replikacja i kondycja';        C = 'DC-NET';       W = 'DC'; T = 'Niedostępne usługi AD na DC' }
    @{ Id = 'DC-SYSVOL-SHARE';   O = 'S'; M = 'Replikacja i kondycja';        C = 'DC-NET';       W = 'DC'; T = 'Brak udziału SYSVOL/NETLOGON' }
    @{ Id = 'DC-TIME';           O = 'S'; M = 'Replikacja i kondycja';        C = 'DC-NET';       W = 'DC'; T = 'Różnica czasu DC względem PDC' }
    @{ Id = 'D-GPO-SYNC';        O = 'S'; M = 'Replikacja i kondycja';        C = 'GPO-SYNC';     W = 'DC'; T = 'GPO niespójne AD-SYSVOL' }
    @{ Id = 'DC-DNS-SRV';        O = 'S'; M = 'Replikacja i kondycja';        C = 'DC-DNS';       W = 'DC'; T = 'Brak rekordów SRV DC' }

    @{ Id = 'P-DA-COUNT';        O = 'P'; M = 'Grupy uprzywilejowane';        C = 'PRIV';         T = 'Ponad 5 członków Domain Admins' }
    @{ Id = 'P-SchemaAdmins';    O = 'P'; M = 'Grupy uprzywilejowane';        C = 'PRIV';         T = 'Niepusta grupa Schema Admins' }
    @{ Id = 'P-AccountOperators'; O = 'P'; M = 'Grupy uprzywilejowane';       C = 'PRIV';         T = 'Niepusta grupa Account Operators' }
    @{ Id = 'P-ServerOperators'; O = 'P'; M = 'Grupy uprzywilejowane';        C = 'PRIV';         T = 'Niepusta grupa Server Operators' }
    @{ Id = 'P-PrintOperators';  O = 'P'; M = 'Grupy uprzywilejowane';        C = 'PRIV';         T = 'Niepusta grupa Print Operators' }
    @{ Id = 'P-BackupOperators'; O = 'P'; M = 'Grupy uprzywilejowane';        C = 'PRIV';         T = 'Niepusta grupa Backup Operators' }
    @{ Id = 'P-PNE';             O = 'P'; M = 'Ochrona kont administratorów'; C = 'PRIV';         T = 'Admini z hasłem bez wygasania' }
    @{ Id = 'P-SPN';             O = 'P'; M = 'Ochrona kont administratorów'; C = 'PRIV';         T = 'Admini z SPN (Kerberoasting)' }
    @{ Id = 'P-DELEG';           O = 'P'; M = 'Ochrona kont administratorów'; C = 'PRIV';         T = 'Admini bez ochrony przed delegacją' }
    @{ Id = 'P-STALE';           O = 'P'; M = 'Ochrona kont administratorów'; C = 'PRIV';         T = 'Nieużywane konta uprzywilejowane' }
    @{ Id = 'P-ADM500';          O = 'P'; M = 'Ochrona kont administratorów'; C = 'PRIV';         T = 'Stare hasło wbudowanego Administratora' }
    @{ Id = 'U-ADMINCOUNT';      O = 'P'; M = 'Ochrona kont administratorów'; C = 'USERS';        T = 'Osierocone adminCount=1' }
    @{ Id = 'U-UNCONSTR';        O = 'P'; M = 'Delegacja';                    C = 'USERS';        T = 'Użytkownicy z delegacją nieograniczoną' }
    @{ Id = 'C-UNCONSTR';        O = 'P'; M = 'Delegacja';                    C = 'COMPUTERS';    T = 'Komputery z delegacją nieograniczoną' }
    @{ Id = 'C-LAPS-READ-BROAD'; O = 'P'; M = 'Dostęp do haseł LAPS';         C = 'LAPS-ACL';     N = 'C-LAPS-NONE'; T = 'Hasła LAPS dla szerokich grup' }
    @{ Id = 'C-LAPS-READABLE';   O = 'P'; M = 'Dostęp do haseł LAPS';         C = 'LAPS-ACL';     N = 'C-LAPS-NONE'; T = 'Konto przeglądu widzi hasła LAPS' }
    @{ Id = 'C-LAPS-READERS';    O = 'P'; M = 'Dostęp do haseł LAPS';         C = 'LAPS-ACL';     N = 'C-LAPS-NONE'; T = 'Podmioty z dostępem do haseł LAPS' }
    @{ Id = 'DC-CIS-RIGHTS';     O = 'P'; M = 'Prawa na kontrolerach domeny'; C = 'CIS';          W = 'DC'; T = 'Przypisanie praw użytkowników na DC' }

    @{ Id = 'D-TRUST-SIDF';      O = 'T'; M = 'Filtrowanie SID';              C = 'DOMAIN';       T = 'Zaufania zewnętrzne bez filtrowania SID' }
    @{ Id = 'D-KRB-TRUST';       O = 'T'; M = 'Szyfrowanie zaufań';           C = 'KRB-ENC';      T = 'Zaufania bez AES' }

    @{ Id = 'P-KRBTGT';          O = 'A'; M = 'Golden Ticket';                C = 'PRIV';         T = 'Stare hasło krbtgt' }
    @{ Id = 'C-LAPS-NONE';       O = 'A'; M = 'Pass-the-hash';                C = 'COMPUTERS';    T = 'LAPS nie wdrożony' }
    @{ Id = 'C-LAPS-MISSING';    O = 'A'; M = 'Pass-the-hash';                C = 'COMPUTERS';    N = 'C-LAPS-NONE'; T = 'Komputery bez LAPS' }
    @{ Id = 'C-LAPS-EXPIRED';    O = 'A'; M = 'Pass-the-hash';                C = 'COMPUTERS';    N = 'C-LAPS-NONE'; T = 'Hasło LAPS przestało się zmieniać' }
    @{ Id = 'C-LAPS-LEGACY';     O = 'A'; M = 'Pass-the-hash';                C = 'COMPUTERS';    N = 'C-LAPS-NONE'; T = 'Przestarzały Microsoft LAPS' }
    @{ Id = 'U-ASREP';           O = 'A'; M = 'Łamanie haseł';                C = 'USERS';        T = 'Konta bez preautentykacji Kerberos' }
    @{ Id = 'U-SPN';             O = 'A'; M = 'Łamanie haseł';                C = 'USERS';        T = 'Konta użytkowników z SPN' }
    @{ Id = 'D-PWDLEN';          O = 'A'; M = 'Łamanie haseł';                C = 'DOMAIN';       T = 'Minimalna długość hasła < 12' }
    @{ Id = 'D-PWDCPLX';         O = 'A'; M = 'Łamanie haseł';                C = 'DOMAIN';       T = 'Złożoność haseł wyłączona' }
    @{ Id = 'D-LOCKOUT';         O = 'A'; M = 'Łamanie haseł';                C = 'DOMAIN';       T = 'Brak blokady konta' }
    @{ Id = 'DC-SPOOLER';        O = 'A'; M = 'Przechwytywanie i relay';      C = 'DC-PROBE';     W = 'DC'; T = 'Print Spooler na DC' }
    @{ Id = 'DC-LDAPSIGN';       O = 'A'; M = 'Przechwytywanie i relay';      C = 'DC-PROBE';     W = 'DC'; T = 'Podpisywanie LDAP niewymagane' }
    @{ Id = 'DC-LDAPCBT';        O = 'A'; M = 'Przechwytywanie i relay';      C = 'DC-PROBE';     W = 'DC'; T = 'LDAP channel binding niewymuszony' }
    @{ Id = 'DC-CIS-AUDIT';      O = 'A'; M = 'Audyt';                        C = 'CIS';          W = 'DC'; T = 'Zasady audytu DC (CIS L1)' }
    @{ Id = 'DC-CIS-REG';        O = 'A'; M = 'Utwardzenie DC';               C = 'CIS';          W = 'DC'; T = 'Ustawienia zabezpieczeń DC (CIS L1)' }
    @{ Id = 'D-BACKUP';          O = 'A'; M = 'Kopia i odtwarzanie';          C = 'BACKUP';       T = 'Brak aktualnej kopii AD' }
    @{ Id = 'D-RECYCLE';         O = 'A'; M = 'Kopia i odtwarzanie';          C = 'DOMAIN';       T = 'Kosz AD wyłączony' }
    @{ Id = 'D-FFL';             O = 'S'; M = 'Przestarzałe systemy';         C = 'DOMAIN';       T = 'Poziom funkcjonalny lasu < 2016' }
    @{ Id = 'DC-REGISTRATION';   O = 'S'; M = 'Replikacja i kondycja';        C = 'DC-REG';       T = 'Konto DC bez kompletnej rejestracji w lesie' }
    @{ Id = 'DC-SUBNET';         O = 'S'; M = 'Replikacja i kondycja';        C = 'SITES';        T = 'Adres DC poza podsieciami AD' }
    @{ Id = 'P-ADMLOGIN';        O = 'P'; M = 'Ochrona kont administratorów'; C = 'PRIV';         T = 'Wbudowany Administrator używany' }
    @{ Id = 'P-PROTECTED';       O = 'P'; M = 'Ochrona kont administratorów'; C = 'PRIV';         T = 'Konta uprzywilejowane spoza Protected Users' }
    @{ Id = 'C-OWNER';           O = 'A'; M = 'Delegacja';                    C = 'COMP-OWNER';   T = 'Komputery z właścicielem spoza administratorów' }
    @{ Id = 'D-PREWIN2000';      O = 'A'; M = 'Uprawnienia domyślne';         C = 'DOMAIN';       T = 'Szerokie grupy w Pre-Windows 2000 Compatible Access' }
    @{ Id = 'D-DSHEURISTICS';    O = 'A'; M = 'Uprawnienia domyślne';         C = 'DOMAIN';       T = 'dSHeuristics osłabia zabezpieczenia' }
    @{ Id = 'D-DNS-CREATECHILD'; O = 'A'; M = 'Przechwytywanie i relay';      C = 'DOMAIN';       T = 'Strefy DNS bez ochrony przed ADIDNS spoofing' }
    @{ Id = 'DC-ANONLDAP';       O = 'A'; M = 'Uprawnienia domyślne';         C = 'DC-PROBE';     W = 'DC'; T = 'Anonimowe zapytania LDAP do DC' }
    @{ Id = 'DC-NETSESSION';     O = 'A'; M = 'Uprawnienia domyślne';         C = 'DC-PROBE';     W = 'DC'; T = 'Wyliczanie sesji SMB na DC (NetCease)' }
    @{ Id = 'D-GPO-LLMNR';       O = 'A'; M = 'Przechwytywanie i relay';      C = 'GPO-ALL';      W = 'DC'; T = 'LLMNR niewyłączony w GPO' }
    @{ Id = 'D-GPO-HARDPATH';    O = 'A'; M = 'Przechwytywanie i relay';      C = 'GPO-ALL';      W = 'DC'; T = 'Hardened UNC Paths dla SYSVOL/NETLOGON' }
    @{ Id = 'D-GPO-PSLOG';       O = 'A'; M = 'Audyt';                        C = 'GPO-ALL';      W = 'DC'; T = 'Rejestrowanie bloków skryptów PowerShell' }
    @{ Id = 'P-ADMINMAIL';       O = 'P'; M = 'Ochrona kont administratorów'; C = 'PRIV';         T = 'Konta uprzywilejowane z adresem e-mail' }
)
# ---------- mapowanie na NIS2 / UKSC i ISO/IEC 27001:2022 ----------
# Rodzaj ryzyka (M z katalogu reguł) -> środki z art. 21 ust. 2 NIS2 (wdrożone w UKSC, Dz. U. 2026 poz. 252) i zabezpieczenia z załącznika A ISO/IEC 27001:2022.
# To wskazanie, których środków dotyczy znalezisko techniczne AD - nie ocena zgodności podmiotu.
$nis2Names = [ordered]@{
    a = 'Analiza ryzyka i polityki bezpieczeństwa systemów informacyjnych'
    b = 'Obsługa incydentów'
    c = 'Ciągłość działania: kopie zapasowe, odtwarzanie, zarządzanie kryzysowe'
    d = 'Bezpieczeństwo łańcucha dostaw'
    e = 'Bezpieczeństwo nabywania, rozwoju i utrzymania systemów, w tym obsługa podatności'
    f = 'Ocena skuteczności środków zarządzania ryzykiem'
    g = 'Podstawowa cyberhigiena i szkolenia'
    h = 'Kryptografia i szyfrowanie'
    i = 'Bezpieczeństwo zasobów ludzkich, kontrola dostępu i zarządzanie aktywami'
    j = 'Uwierzytelnianie wieloskładnikowe i zabezpieczona łączność'
}
$isoNames = [ordered]@{
    '5.9'  = 'Inwentarz informacji i innych powiązanych aktywów'
    '5.15' = 'Kontrola dostępu'
    '5.16' = 'Zarządzanie tożsamością'
    '5.17' = 'Informacje uwierzytelniające'
    '5.18' = 'Prawa dostępu'
    '5.19' = 'Bezpieczeństwo informacji w relacjach z dostawcami'
    '8.2'  = 'Uprzywilejowane prawa dostępu'
    '8.5'  = 'Bezpieczne uwierzytelnianie'
    '8.8'  = 'Zarządzanie podatnościami technicznymi'
    '8.9'  = 'Zarządzanie konfiguracją'
    '8.13' = 'Kopie zapasowe informacji'
    '8.14' = 'Nadmiarowość środków przetwarzania informacji'
    '8.15' = 'Rejestrowanie zdarzeń'
    '8.16' = 'Działania monitorujące'
    '8.17' = 'Synchronizacja zegarów'
    '8.20' = 'Bezpieczeństwo sieci'
    '8.24' = 'Stosowanie kryptografii'
}
$complianceMap = @{
    'Nieaktywne konta'             = @{ N = 'i';    I = '5.16, 5.18' }
    'Konfiguracja kont'            = @{ N = 'g, i'; I = '5.17, 8.5' }
    'Przestarzałe systemy'         = @{ N = 'e';    I = '5.9, 8.8' }
    'Zarządzanie poprawkami'       = @{ N = 'e';    I = '8.8' }
    'Przestarzałe protokoły'       = @{ N = 'e, h'; I = '8.5, 8.24' }
    'Replikacja i kondycja'        = @{ N = 'c, e'; I = '8.9, 8.14, 8.17' }
    'Grupy uprzywilejowane'        = @{ N = 'i';    I = '5.15, 8.2' }
    'Ochrona kont administratorów' = @{ N = 'i, j'; I = '5.17, 8.2' }
    'Delegacja'                    = @{ N = 'i';    I = '8.2, 8.9' }
    'Dostęp do haseł LAPS'         = @{ N = 'i';    I = '5.15, 5.17' }
    'Prawa na kontrolerach domeny' = @{ N = 'i';    I = '8.2, 8.9' }
    'Filtrowanie SID'              = @{ N = 'd, i'; I = '5.15, 5.19' }
    'Szyfrowanie zaufań'           = @{ N = 'd, h'; I = '5.19, 8.24' }
    'Golden Ticket'                = @{ N = 'h, i'; I = '5.17, 8.2' }
    'Pass-the-hash'                = @{ N = 'i';    I = '5.17, 8.5' }
    'Łamanie haseł'                = @{ N = 'g, i'; I = '5.17, 8.5' }
    'Przechwytywanie i relay'      = @{ N = 'h, j'; I = '8.20, 8.24' }
    'Audyt'                        = @{ N = 'b, f'; I = '8.15, 8.16' }
    'Utwardzenie DC'               = @{ N = 'e, g'; I = '8.9' }
    'Kopia i odtwarzanie'          = @{ N = 'c';    I = '8.13' }
    'Uprawnienia domyślne'         = @{ N = 'i';    I = '5.15, 8.9' }
    'Inne'                       = @{ N = 'a';    I = '' }
}

# ---------- plan naprawczy: pracochłonność i etap ----------
# Id -> @(godziny min, godziny max, etap, uwaga). Etap 1 = do 30 dni, 2 = 30-90 dni (wymaga testów), 3 = do 12 miesięcy (projekty).
# Znalezisko Critical zawsze trafia do etapu 1. Godziny: przygotowanie, wdrożenie i weryfikacja w typowej domenie (do ok. 500 kont);
# bez zakupów, licencji i migracji pojedynczych stacji. Szacunki do dostosowania do realnych czasów PEPIX.
$planMeta = @{
    'U-STALE'          = @(2, 4, 1, 'Lista do potwierdzenia z klientem przed wyłączeniem')
    'C-STALE'          = @(1, 3, 1, '')
    'U-PWDNOTREQ'      = @(1, 2, 1, '')
    'U-REVERSIBLE'     = @(1, 2, 1, 'Po zmianie flagi wymusić zmianę hasła')
    'U-PNE'            = @(2, 4, 2, 'Wymaga komunikacji do użytkowników')
    'U-SIDHIST'        = @(2, 4, 2, 'Sprawdzić, czy migracja jest zakończona')
    'U-GUEST'          = @(0.5, 1, 1, '')
    'C-MAQ'            = @(1, 2, 1, 'Wcześniej delegować dołączanie komputerów na OU')
    'C-OS-EOL'         = @(8, 40, 3, 'Projekt migracji; koszt zależy od liczby systemów')
    'C-OS-W10'         = @(4, 16, 3, 'Plan migracji do Windows 11 lub ESU')
    'C-OS-FEATURE'     = @(2, 6, 2, 'Sprawdzić TargetReleaseVersion i zatwierdzenia WSUS')
    'C-OS-SOON'        = @(4, 8, 3, 'Plan migracji serwerów i budżet')
    'DC-OS-EOL'        = @(8, 16, 3, 'Na każdy DC: nowy DC, przeniesienie ról, degradacja starego')
    'D-DFL'            = @(2, 4, 3, 'Po wycofaniu starszych DC (DC-OS-EOL)')
    'DC-PATCH-OLD'     = @(2, 4, 1, 'Restart DC po jednym, przy zdrowej replikacji')
    'DC-PATCH-DIFF'    = @(1, 3, 1, '')
    'DC-REBOOT'        = @(1, 2, 1, 'W oknie serwisowym')
    'U-DES'            = @(1, 2, 1, '')
    'D-KRB-DES'        = @(2, 4, 2, 'Najpierw sprawdzić użycie DES (DC-KRB-DES-USED, -UseWinRM)')
    'D-KRB-NOAES'      = @(2, 6, 2, 'Konta usług - w uzgodnieniu z właścicielami aplikacji')
    'DC-KRB-DES-USED'  = @(4, 8, 2, 'Identyfikacja systemów wymagających DES')
    'DC-KRB-RC4-USED'  = @(8, 16, 2, 'Przygotowanie do wyłączenia RC4')
    'DC-SMB1'          = @(2, 6, 2, 'Najpierw audyt dostępu SMB1')
    'DC-NTLMV1'        = @(4, 12, 2, 'Najpierw audyt zdarzeń 4624 (NTLM V1)')
    'DC-REPL-FAIL'     = @(2, 8, 1, '')
    'DC-REPL-STALE'    = @(2, 8, 1, '')
    'DC-REPL-TSL'      = @(4, 12, 1, 'Nie wymuszać replikacji - izolacja i ponowna promocja DC')
    'D-SINGLEDC'       = @(6, 12, 2, 'Wymaga serwera/licencji na drugi DC')
    'D-SYSVOL-FRS'     = @(4, 8, 2, 'Przy zdrowej replikacji AD')
    'D-FSMO'           = @(2, 4, 1, '')
    'DC-MACHINEPWD'    = @(1, 4, 1, '')
    'DC-PORTS'         = @(1, 4, 1, '')
    'DC-SYSVOL-SHARE'  = @(2, 6, 1, '')
    'DC-TIME'          = @(1, 3, 1, '')
    'D-GPO-SYNC'       = @(2, 4, 1, '')
    'DC-DNS-SRV'       = @(1, 2, 1, '')
    'P-DA-COUNT'       = @(2, 6, 1, 'Wymaga decyzji klienta, kto pozostaje administratorem')
    'P-SchemaAdmins'   = @(1, 2, 1, '')
    'P-AccountOperators' = @(1, 2, 1, '')
    'P-ServerOperators' = @(1, 2, 1, '')
    'P-PrintOperators' = @(1, 2, 1, '')
    'P-BackupOperators' = @(1, 2, 1, 'Sprawdzić, czy grupy nie używa oprogramowanie do kopii')
    'P-PNE'            = @(2, 4, 1, '')
    'P-SPN'            = @(2, 4, 1, 'Konta usług przenieść na gMSA')
    'P-DELEG'          = @(2, 4, 2, 'Protected Users najpierw na kontach testowych')
    'P-STALE'          = @(1, 2, 1, '')
    'P-ADM500'         = @(0.5, 1, 1, 'Nowe hasło do sejfu haseł')
    'U-ADMINCOUNT'     = @(1, 3, 2, '')
    'U-UNCONSTR'       = @(2, 8, 2, 'Analiza usług korzystających z delegacji')
    'C-UNCONSTR'       = @(2, 8, 2, 'Analiza usług korzystających z delegacji')
    'C-LAPS-READ-BROAD' = @(1, 3, 1, 'Po zmianie wymusić rotację haseł LAPS')
    'C-LAPS-READABLE'  = @(1, 2, 1, '')
    'C-LAPS-READERS'   = @(2, 4, 2, 'Przegląd z klientem')
    'DC-CIS-RIGHTS'    = @(2, 6, 2, '')
    'D-TRUST-SIDF'     = @(2, 4, 2, 'Uzgodnienie z administratorem domeny zaufanej')
    'D-KRB-TRUST'      = @(1, 3, 2, 'Po obu stronach relacji')
    'P-KRBTGT'         = @(2, 4, 1, 'Dwukrotna zmiana z odstępem; najpierw tryb symulacji')
    'C-LAPS-NONE'      = @(8, 16, 2, 'Wdrożenie Windows LAPS przez GPO')
    'C-LAPS-MISSING'   = @(2, 8, 2, '')
    'C-LAPS-EXPIRED'   = @(1, 4, 1, '')
    'C-LAPS-LEGACY'    = @(4, 12, 3, 'Migracja na Windows LAPS')
    'U-ASREP'          = @(1, 2, 1, '')
    'U-SPN'            = @(2, 8, 2, 'Migracja kont usług na gMSA')
    'D-PWDLEN'         = @(2, 4, 2, 'Komunikacja do użytkowników; zmiana działa przy kolejnej zmianie hasła')
    'D-PWDCPLX'        = @(1, 2, 2, '')
    'D-LOCKOUT'        = @(1, 2, 1, '')
    'DC-SPOOLER'       = @(1, 2, 1, 'Sprawdzić, czy DC nie jest serwerem wydruku')
    'DC-LDAPSIGN'      = @(4, 12, 2, 'Najpierw zdarzenia 2889 i poprawa klientów')
    'DC-LDAPCBT'       = @(4, 8, 2, 'Najpierw tryb "gdy obsługiwane" i zdarzenia 3039')
    'DC-CIS-AUDIT'     = @(4, 8, 1, 'Zwiększyć dziennik Security; przekazywanie do SIEM')
    'DC-CIS-REG'       = @(8, 24, 2, 'Etapami, po teście zgodności aplikacji')
    'D-BACKUP'         = @(4, 8, 1, 'Z testem odtworzenia')
    'D-RECYCLE'        = @(0.5, 1, 1, '')
    'D-FFL'            = @(1, 2, 3, 'Po wycofaniu starszych DC we wszystkich domenach lasu')
    'DC-REGISTRATION'  = @(2, 4, 1, 'Najpierw potwierdzić z klientem, że serwer nie istnieje')
    'DC-SUBNET'        = @(1, 3, 1, 'Lista segmentów sieci od klienta')
    'P-ADMLOGIN'       = @(1, 4, 2, 'Ustalić, kto i skąd używa konta; usługi przenieść na gMSA')
    'P-PROTECTED'      = @(2, 6, 2, 'Etapami, najpierw konto testowe')
    'C-OWNER'          = @(1, 4, 2, 'Zmiana właściciela skryptem; razem z C-MAQ')
    'D-PREWIN2000'     = @(1, 3, 2, 'Test zgodności starszych systemów i urządzeń')
    'D-DSHEURISTICS'   = @(1, 2, 2, 'Ustalić przyczynę zmiany przed przywróceniem')
    'D-DNS-CREATECHILD' = @(1, 3, 2, 'Rekord wildcard w każdej strefie; uzgodnić adres docelowy')
    'DC-ANONLDAP'      = @(1, 4, 1, 'Najpierw ustalić urządzenia korzystające z anonimowego LDAP')
    'DC-NETSESSION'    = @(1, 3, 2, 'Restart usługi Server w oknie serwisowym')
    'D-GPO-LLMNR'      = @(1, 2, 1, 'Razem z wyłączeniem NetBIOS przez DHCP')
    'D-GPO-HARDPATH'   = @(0.5, 2, 1, '')
    'D-GPO-PSLOG'      = @(1, 4, 2, 'Rozmiar dziennika i przekazywanie do SIEM')
    'P-ADMINMAIL'      = @(1, 3, 2, 'Wymaga osobnych kont dla administratorów')
}
# Zwykła tabela, nie [ordered]: w OrderedDictionary indeks liczbowy oznacza pozycję, nie klucz. Kolejność: 1..3.
$planStages = @{
    1 = 'Etap 1 - do 30 dni: działania szybkie i problemy krytyczne'
    2 = 'Etap 2 - 30-90 dni: zmiany wymagające testów i uzgodnień'
    3 = 'Etap 3 - do 12 miesięcy: projekty (migracje, modernizacja)'
}
function Format-Hours($H) { if ($null -eq $H) { '?' } else { ([double]$H).ToString('0.#', [System.Globalization.CultureInfo]'pl-PL') } }

$ruleMeta = @{}
foreach ($r in $ruleCatalog) { $ruleMeta[$r.Id] = $r }
$sevLevel = @{ Critical = 1; High = 2; Medium = 3; Low = 4; Info = 5 }

function Add-Finding([hashtable]$F) {
    $obj  = @($F.Objects | Where-Object { $_ })
    $rule = $ruleMeta[$F.Id]
    $row  = [pscustomobject]@{
        Id             = $F.Id
        Category       = $F.Category
        Severity       = $F.Severity
        Title          = $F.Title
        Count          = $obj.Count
        Description    = [string]$F.Description
        Recommendation = [string]$F.Recommendation
        Fix            = [string]$F.Fix
        Mitre          = [string]$F.Mitre
        Obszar         = $(if ($F.Severity -eq 'Info') { 'Informacje' } elseif ($rule) { $areaNames[$rule.O] } else { $areaNames['A'] })
        Model          = $(if ($rule) { $rule.M } else { 'Inne' })
        Poziom         = $sevLevel[$F.Severity]
        NIS2           = ''
        ISO27001       = ''
        Objects        = $obj
    }
    if ($F.Severity -ne 'Info' -and $complianceMap.ContainsKey($row.Model)) {
        $row.NIS2     = $complianceMap[$row.Model].N
        $row.ISO27001 = $complianceMap[$row.Model].I
    }
    $findings.Add($row)
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

# Czy adres IPv4 należy do podsieci w zapisie CIDR ("10.0.0.0/24"); IPv6 i błędny zapis = $false
function Test-IpInSubnet([string]$Ip, [string]$Cidr) {
    if ($Cidr -notmatch '^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$') { return $false }
    $len = [int]$Matches[2]; $netTxt = $Matches[1]
    $a = $null; $n = $null
    if ($len -gt 32 -or -not [System.Net.IPAddress]::TryParse($Ip, [ref]$a) -or -not [System.Net.IPAddress]::TryParse($netTxt, [ref]$n)) { return $false }
    if ($a.AddressFamily -ne 'InterNetwork') { return $false }
    $toNum = { param($x) $b = $x.GetAddressBytes(); ([uint64]$b[0] * 16777216) + ([uint64]$b[1] * 65536) + ([uint64]$b[2] * 256) + [uint64]$b[3] }
    $mask = [uint64]4294967296 - [uint64][math]::Pow(2, 32 - $len)
    ((& $toNum $a) -band $mask) -eq ((& $toNum $n) -band $mask)
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
        $gpLink = (Get-LdapObject -Identity $container -Properties gPLink).gplink
        if (-not $gpLink) { continue }
        foreach ($m in [regex]::Matches($gpLink, '\[LDAP://([^;\]]+);(\d+)\]')) {
            if ([int]$m.Groups[2].Value -band 1) { continue }
            $gpo = Get-LdapObject -Identity $m.Groups[1].Value -Properties displayName, gPCFileSysPath, flags
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
        $gpLink = (Get-LdapObject -Identity $container -Properties gPLink).gplink
        if (-not $gpLink) { continue }
        foreach ($m in [regex]::Matches($gpLink, '\[LDAP://([^;\]]+);(\d+)\]')) {
            if ([int]$m.Groups[2].Value -band 1) { continue }
            $gpo = Get-LdapObject -Identity $m.Groups[1].Value -Properties displayName, gPCFileSysPath, flags
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

# Wszystkie GPO z włączonym łączem (domena, OU, lokacje) -> wpisy rejestru komputera z Registry.pol i preferencji (Registry.xml).
# Bez kolejności, filtrów zabezpieczeń i WMI: odpowiada na pytanie "czy któreś GPO ustawia X", a nie "co dostaje dany komputer".
function Get-LinkedGpoRegistry {
    $links = @{}
    $holders = @(Find-Ldap -Filter '(gPLink=*)' -Properties gPLink) + @(Find-Ldap -SearchBase "CN=Sites,$configDn" -Filter '(gPLink=*)' -Properties gPLink)
    foreach ($h in $holders) {
        foreach ($m in [regex]::Matches("$($h.gplink)", '\[LDAP://([^;\]]+);(\d+)\]')) {
            if (-not ([int]$m.Groups[2].Value -band 1)) { $links[$m.Groups[1].Value.ToLower()] = $true }
        }
    }
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($dn in $links.Keys) {
        $gpo = $null
        try { $gpo = Get-LdapObject -Identity $dn -Properties displayName, gPCFileSysPath, flags } catch { $gpo = $null }
        if (-not $gpo -or ([int]$gpo.flags -band 2) -or -not $gpo.gpcfilesyspath) { continue }
        $root = Join-Path $gpo.gpcfilesyspath 'Machine'
        $polFile = Join-Path $root 'Registry.pol'
        if (Test-Path -LiteralPath $polFile) {
            foreach ($e in @(Read-RegistryPol ([System.IO.File]::ReadAllBytes($polFile)))) {
                $out.Add([pscustomobject]@{ Gpo = $gpo.displayname; Key = $e.Key; Name = $e.Name; Data = $e.Data; Deleted = $e.Deleted })
            }
        }
        $xmlFile = Join-Path $root 'Preferences\Registry\Registry.xml'
        if (Test-Path -LiteralPath $xmlFile) {
            $x = $null
            try { $x = [xml](Get-Content -LiteralPath $xmlFile -Raw) } catch { $x = $null }
            foreach ($p in @($x.SelectNodes('//Properties') | Where-Object { $_ })) {
                if ($p.hive -ne 'HKEY_LOCAL_MACHINE' -or $p.action -eq 'D') { continue }
                $d = $p.value
                if ($p.type -eq 'REG_DWORD') { try { $d = [Convert]::ToInt64($p.value, 16) } catch { $d = $p.value } }
                $out.Add([pscustomobject]@{ Gpo = "$($gpo.displayname) (preferencje)"; Key = $p.key; Name = $p.name; Data = $d; Deleted = $false })
            }
        }
    }
    $out
}

# Znaki dSHeuristics (numeracja od 1, jak w dokumentacji MS-ADTS); brak znaku = wartość domyślna '0'
function Get-DsHeuristicsChar([string]$Value, [int]$Position) {
    if ($Value.Length -ge $Position) { "$($Value[$Position - 1])" } else { '0' }
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
# Bity msDS-SupportedEncryptionTypes -> tekst (0x1 DES-CBC-CRC, 0x2 DES-CBC-MD5, 0x4 RC4, 0x8 AES128, 0x10 AES256)
function Format-EncTypes($Value) {
    if ($null -eq $Value -or "$Value" -eq '0') { return 'nieustawione (domyślne KDC, zwykle z RC4)' }
    $n = [int64]$Value; $t = @()
    if ($n -band 1)    { $t += 'DES-CRC' }
    if ($n -band 2)    { $t += 'DES-MD5' }
    if ($n -band 4)    { $t += 'RC4' }
    if ($n -band 8)    { $t += 'AES128' }
    if ($n -band 0x10) { $t += 'AES256' }
    "$n ($($t -join ', '))"
}
#endregion

#region ---------- dane bazowe i inwentaryzacja ----------
$dcs = @(Get-LdapDomainControllers)
$pp  = Get-LdapPasswordPolicy
$trusts = @()
try { $trusts = @(Get-LdapTrusts) } catch { $trusts = @() }

# Atrybuty LDAP kont (UAC, SID, pwdLastSet, lastLogonTimestamp, whenCreated pobiera zawsze Find-Ldap)
$userProps = 'servicePrincipalName','memberOf','adminCount','sIDHistory','msDS-SupportedEncryptionTypes','mail'

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
        $m = @(Get-LdapGroupUsers -GroupSid $g.Value -Properties $userProps)
        $groupMembers[$g.Key] = $m
        foreach ($u in $m) { $privSids[$u.SID.Value] = $u }
    } catch {
        Add-Finding @{ Id = 'ERR-PRIV'; Category = 'Błędy testów'; Severity = 'Info'
                       Title = "Nie odczytano grupy $($g.Key): $($_.Exception.Message)" }
    }
}
$privBySid = @{}
foreach ($sid in $privSids.Keys) { $privBySid[$sid] = $privSids[$sid] }
$privUsers = @($privBySid.Values)
# Konto uruchamiające jest w grupie uprzywilejowanej (rekursywnie) - sondy uprawnień zwykłego konta są wtedy niemiarodajne
$runAsPriv = $false
try { $runAsPriv = $privBySid.ContainsKey([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value) } catch { $runAsPriv = $false }
function Get-GroupRows([string]$Name) { @($groupMembers[$Name]) | ForEach-Object { ConvertTo-UserRow $privBySid[$_.SID.Value] } }

$protectedUsersDn = $null
try { $protectedUsersDn = (Get-LdapObject -Identity "$dSid-525").distinguishedname } catch { $protectedUsersDn = $null }

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
                    ConvertTo-UserRow $_ | Add-Member -NotePropertyName SPN -NotePropertyValue ($_.ServicePrincipalName -join ', ') -PassThru |
                    Add-Member -NotePropertyName Szyfrowanie -NotePropertyValue (Format-EncTypes $_.'msDS-SupportedEncryptionTypes') -PassThru })
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

    $adm = Get-LdapObject -Identity "$dSid-500"
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
    # lastLogonTimestamp replikuje się z opóźnieniem do ok. 14 dni - próg 35 dni jak w typowych narzędziach audytowych
    if ($adm.Enabled -and $adm.LastLogonDate -and $adm.LastLogonDate -gt $now.AddDays(-35)) {
        Add-Finding @{
            Id = 'P-ADMLOGIN'; Category = $catPriv; Severity = 'Medium'
            Title = "Wbudowane konto Administrator używane w ostatnich 35 dniach (ostatnio: $(Format-Date $adm.LastLogonDate))"
            Objects = (ConvertTo-UserRow $adm)
            Description = 'Konto Administrator (RID 500) jest wspólne - z logów nie wynika, kto go użył - i nie podlega blokadzie po błędnych hasłach, więc jest pierwszym celem zgadywania haseł. Regularne użycie oznacza zwykle, że administratorzy nie mają kont imiennych, hasło zna wiele osób albo na tym koncie działają usługi lub zadania zaplanowane. Data pochodzi z lastLogonTimestamp (dokładność do ok. 14 dni).'
            Recommendation = 'Administrować z imiennych kont. Konto Administrator zostawić jako awaryjne z hasłem w sejfie haseł. Ustalić w dzienniku Security DC (zdarzenia 4624/4768), skąd następują logowania, i przenieść usługi oraz zadania na gMSA.'
            Fix = (Fx 'Get-WinEvent -ComputerName <DC> -LogName Security -FilterXPath "*[System[EventID=4768] and EventData[Data[@Name=''TargetSid'']=''{SID}-500'']]" -MaxEvents 50 | Format-List TimeCreated, Message')
            Mitre = 'T1078.002'
        }
    }

    Add-IfAny @{
        Id = 'P-ADMINMAIL'; Category = $catPriv; Severity = 'Low'
        Title = 'Konta uprzywilejowane z adresem e-mail'
        Objects = ($en | Where-Object { $_.mail } | ForEach-Object { ConvertTo-UserRow $_ | Add-Member -NotePropertyName Email -NotePropertyValue $_.mail -PassThru })
        Description = 'Adres e-mail na koncie administracyjnym zwykle oznacza, że administrator czyta pocztę z tego konta. Złośliwy załącznik lub link otwarty w takiej sesji działa wtedy z uprawnieniami administratora domeny; konto jest też widoczne w książce adresowej i narażone na phishing.'
        Recommendation = 'Rozdzielić konta: imienne konto zwykłe (poczta, internet) i osobne konto administracyjne bez skrzynki i bez adresu e-mail.'
        Fix = (Fx 'Set-ADUser -Identity <konto_admin> -Clear mail')
        Mitre = 'T1566'
    }

    # Protected Users (RID 525) rekursywnie; grupa istnieje, gdy w domenie był PDC z Windows Server 2012 R2+
    if ($protectedUsersDn) {
        $puSids = @{}
        foreach ($u in @(Get-LdapGroupUsers -GroupSid "$dSid-525")) { $puSids[$u.SID.Value] = $true }
        Add-IfAny @{
            Id = 'P-PROTECTED'; Category = $catPriv; Severity = 'Low'
            Title = 'Konta uprzywilejowane spoza grupy Protected Users'
            Objects = ($en | Where-Object { -not $puSids.ContainsKey($_.SID.Value) -and -not $_.ServicePrincipalName -and $_.SID.Value -ne "$dSid-500" } |
                       ForEach-Object { ConvertTo-UserRow $_ })
            Description = "Członkowie Protected Users nie mogą używać NTLM, DES ani RC4, ich poświadczenia nie są buforowane (m.in. w LSASS w postaci umożliwiającej pass-the-hash) ani delegowane, a bilet TGT jest ważny 4 h. Ochrona po stronie DC wymaga poziomu funkcjonalnego domeny 2012 R2 (obecnie: $($domain.DomainMode)). Pominięto konta z SPN (usługi) i wbudowanego Administratora (konto awaryjne)."
            Recommendation = 'Dodawać imienne konta administratorów stopniowo, najpierw konto testowe (logowanie RDP, narzędzia używające NTLM, uwierzytelnianie po adresie IP). Nie dodawać kont usług ani komputerów; zostawić co najmniej jedno konto awaryjne poza grupą.'
            Fix = (Fx 'Add-ADGroupMember -Identity ''{SID}-525'' -Members <konto>   # Protected Users')
            Mitre = 'T1550.002'
        }
    } else {
        Add-Finding @{
            Id = 'P-PROTECTED'; Category = $catPriv; Severity = 'Low'
            Title = 'Brak grupy Protected Users w domenie'
            Description = 'Grupa powstaje, gdy rolę PDC przejmie DC z Windows Server 2012 R2 lub nowszym. Bez niej nie można objąć kont administratorów dodatkową ochroną przed kradzieżą poświadczeń.'
            Recommendation = 'Przenieść rolę PDC na DC z aktualnym systemem (patrz DC-OS-EOL).'
            Fix = (Fx 'Move-ADDirectoryServerOperationMasterRole -Identity <DC_2016+> -OperationMasterRole PDCEmulator')
            Mitre = 'T1550.002'
        }
    }

    $krb = Get-LdapObject -Identity krbtgt
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
    $users = @(Find-Ldap -Properties $userProps -Filter '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))')

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
                    ConvertTo-UserRow $_ | Add-Member -NotePropertyName SPN -NotePropertyValue ($_.ServicePrincipalName -join ', ') -PassThru |
                    Add-Member -NotePropertyName Szyfrowanie -NotePropertyValue (Format-EncTypes $_.'msDS-SupportedEncryptionTypes') -PassThru })
        Description = 'Każdy użytkownik domeny może pobrać bilet TGS dla tych kont i łamać ich hasła offline. Konta usług mają często słabe, niezmieniane hasła. Kolumna Szyfrowanie: przy RC4 lub wartości nieustawionej bilet jest szyfrowany RC4, które łamie się wielokrotnie szybciej niż AES.'
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

    $guest = Get-LdapObject -Identity "$dSid-501"
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
    Find-Ldap -SearchBase $rootDse.schemaNamingContext -Properties lDAPDisplayName, schemaIDGUID -Filter (
        '(|(lDAPDisplayName=ms-Mcs-AdmPwd)(lDAPDisplayName=ms-Mcs-AdmPwdExpirationTime)(lDAPDisplayName=msLAPS-Password)' +
        '(lDAPDisplayName=msLAPS-EncryptedPassword)(lDAPDisplayName=msLAPS-PasswordExpirationTime))') |
        ForEach-Object { $lapsSchema[$_.lDAPDisplayName] = [guid]::new([byte[]]$_.schemaIDGUID) }
    $lapsAttrs = @('ms-Mcs-AdmPwdExpirationTime', 'msLAPS-PasswordExpirationTime' | Where-Object { $lapsSchema.ContainsKey($_) })

    $props = @('operatingSystem','operatingSystemVersion','primaryGroupID') + $lapsAttrs
    $comps = @(Find-Ldap -Properties $props -Filter '(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))')
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
        # Tylko Windows: Linux/NAS/klastry (CNO/VCO) i obiekty bez operatingSystem nie mają klienta LAPS
        $lapsSkip = @($nonDc | Where-Object { $_.OperatingSystem -notmatch 'Windows|Hyper-V' }).Count
        $lapsRows = @(foreach ($c in ($nonDc | Where-Object { $_.OperatingSystem -match 'Windows|Hyper-V' })) {
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
            Description = "Te komputery nie mają hasła lokalnego administratora zarządzanego przez LAPS (LAPS ma $covered z $($lapsRows.Count) aktywnych kont komputerów Windows poza DC; pominięte konta bez systemu Windows w atrybucie operatingSystem: $lapsSkip). Ich lokalne hasło administratora jest prawdopodobnie wspólne z innymi komputerami."
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

    $maq = $dObj.'ms-ds-machineaccountquota'
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

#region ---------- komputery: właściciel obiektu ----------
# Komputer dołączony przez zwykłe konto (MachineAccountQuota lub delegacja) ma je jako właściciela obiektu.
# Właściciel może zmienić ACL, a więc ustawić RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity) i przejąć komputer
# albo nadać sobie odczyt hasła LAPS. Odczyt właściciela (SecurityMasks Owner) działa na zwykłym koncie.
Invoke-Check 'COMP-OWNER' {
    $okOwners = @("$dSid-512", "$dSid-519", "$dSid-516", 'S-1-5-32-544', 'S-1-5-32-548', 'S-1-5-18')
    $sidName  = @{}
    $resolve  = {
        param([string]$Sid)
        if (-not $sidName.ContainsKey($Sid)) {
            $o = $null
            try { $o = Get-LdapObject -Identity $Sid } catch { $o = $null }
            $sidName[$Sid] = $(if ($o.sAMAccountName) { $o.sAMAccountName } else { $Sid })
        }
        $sidName[$Sid]
    }
    $created = @(Find-Ldap -SecurityDescriptor -Properties nTSecurityDescriptor, operatingSystem, primaryGroupID, 'mS-DS-CreatorSID' -Filter (
                '(&(objectCategory=computer)(mS-DS-CreatorSID=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))') |
                Where-Object { [int]$_.primarygroupid -notin 516, 521 })
    $noSd = @($created | Where-Object { $_.ntsecuritydescriptor -isnot [System.DirectoryServices.ActiveDirectorySecurity] }).Count
    $rows = foreach ($c in $created) {
        if ($c.ntsecuritydescriptor -isnot [System.DirectoryServices.ActiveDirectorySecurity]) { continue }
        $owner = "$($c.ntsecuritydescriptor.GetOwner([System.Security.Principal.SecurityIdentifier]))"
        if ($owner -in $okOwners) { continue }
        $creator = ''
        try { $creator = "$([System.Security.Principal.SecurityIdentifier]::new([byte[]]$c.'ms-ds-creatorsid', 0))" } catch { $creator = '' }
        ConvertTo-ComputerRow $c |
            Add-Member -NotePropertyName Wlasciciel -NotePropertyValue (& $resolve $owner) -PassThru |
            Add-Member -NotePropertyName Utworzyl -NotePropertyValue $(if ($creator) { & $resolve $creator } else { '' }) -PassThru
    }
    Add-IfAny @{
        Id = 'C-OWNER'; Category = $catComp; Severity = 'Medium'
        Title = 'Komputery, których właścicielem jest konto spoza administratorów'
        Objects = $rows
        Description = 'Te komputery dołączyło do domeny zwykłe konto (przez MachineAccountQuota lub delegację na OU) i nadal jest właścicielem ich obiektu w AD. Właściciel może zmienić uprawnienia obiektu, a przez to ustawić delegację RBCD i uzyskać uprawnienia administratora na komputerze albo nadać sobie odczyt hasła LAPS. Przejęcie takiego konta (np. konta technika używanego do dołączania stacji) daje dostęp do wszystkich dołączonych przez nie komputerów.'
        Recommendation = 'Zmienić właściciela obiektów na Domain Admins. Dołączanie komputerów robić kontem z delegacją na wybrane OU (nie przez MachineAccountQuota - patrz C-MAQ) i po dołączeniu przywracać właściciela. Sprawdzić, czy na tych komputerach nie ustawiono msDS-AllowedToActOnBehalfOfOtherIdentity.'
        Fix = (Fx '$c = Get-ADComputer <komputer>; $acl = Get-Acl "AD:$($c.DistinguishedName)"',
                  '$acl.SetOwner([System.Security.Principal.SecurityIdentifier]''{SID}-512''); Set-Acl -Path "AD:$($c.DistinguishedName)" -AclObject $acl',
                  'Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity | Where-Object msDS-AllowedToActOnBehalfOfOtherIdentity')
        Mitre = 'T1134'
    }
    if ($noSd) {
        Add-Finding @{ Id = 'C-OWNER-UNKNOWN'; Category = 'Błędy testów'; Severity = 'Info'
                       Title = "Nie odczytano właściciela $noSd z $($created.Count) kont komputerów utworzonych przez użytkowników (mS-DS-CreatorSID)"
                       Description = 'Brak uprawnienia do odczytu deskryptora zabezpieczeń - test C-OWNER nie objął tych obiektów.' }
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
        $sd = (Get-LdapObject -Identity $ou -Properties nTSecurityDescriptor -SecurityDescriptor).ntsecuritydescriptor
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
            Objects = (Find-Ldap -Filter "(&(objectCategory=computer)$flt)" -Properties operatingSystem | ForEach-Object { ConvertTo-ComputerRow $_ })
            Description = 'Konto spoza grup uprzywilejowanych, którym uruchomiono przegląd, ma dostęp do jawnych haseł lokalnego administratora tych komputerów. Wartości haseł nie zostały pobrane ani zapisane w raporcie.'
            Recommendation = 'Ustalić, skąd pochodzi dostęp (patrz C-LAPS-READERS / C-LAPS-READ-BROAD) i czy jest uzasadniony dla tego konta.'
            Fix = (Fx 'Find-LapsADExtendedRights -Identity ''<DN OU>''')
            Mitre = 'T1555'
        }
    }
}
#endregion

#region ---------- Kerberos: słabe szyfrowanie (DES, RC4) ----------
# Konfiguracja: atrybut msDS-SupportedEncryptionTypes kont, komputerów, gMSA i zaufań (zwykłe konto).
# Użycie: zdarzenia 4768/4769 z typem szyfrowania biletu DES/RC4 w dzienniku Security DC (tylko -UseWinRM, wymaga audytu Kerberos).
$krbEventDays = 7
Invoke-Check 'KRB-ENC' {
    $kdcRows = [System.Collections.Generic.List[object]]::new()
    $usage   = [System.Collections.Generic.List[object]]::new()
    $krbUnk  = [System.Collections.Generic.List[object]]::new()
    $encName = @{ '0x1' = 'DES-CBC-CRC'; '0x3' = 'DES-CBC-MD5'; '0x17' = 'RC4-HMAC'; '0x18' = 'RC4-HMAC-EXP' }

    if ($UseWinRM -and -not $SkipDCChecks) {
        foreach ($dc in $dcs) {
            try {
                $r = Invoke-Command -ComputerName $dc.HostName -ErrorAction Stop -ArgumentList $krbEventDays -ScriptBlock {
                    param([int]$Days)
                    $ms = [int64]$Days * 86400000
                    $xp = "*[System[(EventID=4768 or EventID=4769) and TimeCreated[timediff(@SystemTime) <= $ms]]] and " +
                          "*[EventData[Data[@Name='TicketEncryptionType']='0x1' or Data[@Name='TicketEncryptionType']='0x3' or " +
                          "Data[@Name='TicketEncryptionType']='0x17' or Data[@Name='TicketEncryptionType']='0x18']]"
                    $kdc = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\KDC' -ErrorAction SilentlyContinue).DefaultDomainSupportedEncTypes
                    $ev  = @(Get-WinEvent -LogName Security -FilterXPath $xp -MaxEvents 5000 -ErrorAction SilentlyContinue)
                    $grp = @($ev | ForEach-Object {
                        $d = @{}; foreach ($n in ([xml]$_.ToXml()).Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
                        [pscustomobject]@{ Typ = $d['TicketEncryptionType']; Konto = $d['TargetUserName']; Usluga = $d['ServiceName']; Adres = $d['IpAddress'] }
                    } | Group-Object Typ, Konto, Usluga, Adres | ForEach-Object {
                        $f = $_.Group[0]
                        [pscustomobject]@{ Typ = $f.Typ; Konto = $f.Konto; Usluga = $f.Usluga; Adres = $f.Adres; Liczba = $_.Count }
                    })
                    [pscustomobject]@{ Kdc = $kdc; Grupy = $grp; Razem = $ev.Count }
                }
                if ($null -ne $r.Kdc -and ([int64]$r.Kdc -band 3)) {
                    $kdcRows.Add([pscustomobject]@{ Obiekt = $dc.HostName; Typ = 'KDC: DefaultDomainSupportedEncTypes (rejestr DC)'; Szyfrowanie = (Format-EncTypes $r.Kdc); Kontener = '' })
                }
                foreach ($g in @($r.Grupy)) {
                    $row = [pscustomobject]@{
                        DC = $dc.HostName; Szyfrowanie = $(if ($encName.ContainsKey("$($g.Typ)")) { $encName["$($g.Typ)"] } else { "$($g.Typ)" })
                        Konto = $g.Konto; Usluga = $g.Usluga; AdresKlienta = $g.Adres; Bilety = $g.Liczba; Kod = "$($g.Typ)"
                    }
                    $usage.Add($row)
                }
            } catch {   # brak WinRM / dostępu do dziennika - pozostałe testy działają dalej
                $krbUnk.Add([pscustomobject]@{ DC = $dc.HostName; Blad = $_.Exception.Message })
            }
        }
    }

    # DES dopuszczony w konfiguracji: bity 0x1/0x2 w msDS-SupportedEncryptionTypes albo komputer z USE_DES_KEY_ONLY (użytkownicy: U-DES)
    $desObj = @(Find-Ldap -Properties 'msDS-SupportedEncryptionTypes' -Filter (
                '(|(msDS-SupportedEncryptionTypes:1.2.840.113556.1.4.804:=3)' +
                '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=2097152)))') |
                Where-Object { -not ($_.userAccountControl -band 2) })
    $desRows = @($desObj | ForEach-Object {
        $enc = Format-EncTypes $_.'msDS-SupportedEncryptionTypes'
        if ($_.userAccountControl -band 0x200000) { $enc = "$enc + USE_DES_KEY_ONLY" }
        [pscustomobject]@{ Obiekt = $(if ($_.sAMAccountName) { $_.sAMAccountName } else { $_.Name }); Typ = $_.ObjectClass; Szyfrowanie = $enc; Kontener = (Get-ParentOU $_.DistinguishedName) }
    }) + @($kdcRows)

    Add-IfAny @{
        Id = 'D-KRB-DES'; Category = $catKrb; Severity = 'High'
        Title = 'Konfiguracja dopuszczająca szyfrowanie DES w Kerberos'
        Objects = $desRows
        Description = 'DES jest złamany - bilety Kerberos zaszyfrowane DES można odszyfrować w krótkim czasie i podszyć się pod konto lub usługę. Windows Server 2025 i Windows 11 24H2 nie obsługują już DES, więc takie ustawienia to także pozostałość po starych systemach/aplikacjach.'
        Recommendation = 'Usunąć DES z obsługiwanych typów szyfrowania (zostawić AES128/AES256), wyłączyć flagę "Use only Kerberos DES encryption types". Zmienić hasło konta, aby wygenerować klucze AES.'
        Fix = (Fx 'Set-ADUser -Identity <konto> -KerberosEncryptionType AES128,AES256', 'Set-ADComputer -Identity <komputer> -KerberosEncryptionType AES128,AES256', 'Set-ADAccountControl -Identity ''<komputer>$'' -UseDESKeyOnly $false')
        Mitre = 'T1558'
    }

    # Konta bez kluczy AES: hasło ustawione przed pierwszym DC 2008+ (data utworzenia grupy Read-only Domain Controllers, RID 521)
    $aesSince = (Get-LdapObject -Identity "$dSid-521").whencreated
    $ft = $aesSince.ToFileTime()
    $noAes = @(Find-Ldap -Filter (
               "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(pwdLastSet>=1)(pwdLastSet<=$ft))"))
    $krbtgt = Get-LdapObject -Identity krbtgt
    if ($krbtgt.PasswordLastSet -and $krbtgt.PasswordLastSet -lt $aesSince) { $noAes += $krbtgt }
    Add-IfAny @{
        Id = 'D-KRB-NOAES'; Category = $catKrb
        Severity = $(if (@($noAes | Where-Object { $privSids[$_.SID.Value] -or $_.SamAccountName -eq 'krbtgt' }).Count) { 'High' } else { 'Medium' })
        Title = 'Konta bez kluczy AES (hasło sprzed wprowadzenia AES w domenie)'
        Objects = ($noAes | ForEach-Object {
            ConvertTo-UserRow $_ | Add-Member -NotePropertyName Uprzywilejowane -NotePropertyValue $(if ($privSids[$_.SID.Value] -or $_.SamAccountName -eq 'krbtgt') { 'Tak' } else { '' }) -PassThru })
        Description = "Klucze AES powstają dopiero przy zmianie hasła na DC Windows Server 2008 lub nowszym (pierwszy taki DC w domenie: $(Format-Date $aesSince)). Te konta mają tylko klucze RC4/DES - Kerberos używa dla nich słabego szyfrowania, a po wyłączeniu RC4 przestaną działać."
        Recommendation = 'Zmienić hasła tych kont (konta usług - w uzgodnieniu z właścicielem aplikacji). Hasło krbtgt zmieniać dwukrotnie zgodnie z procedurą (patrz P-KRBTGT).'
        Fix = (Fx 'Set-ADAccountPassword -Identity <konto> -Reset', 'Set-ADUser -Identity <konto> -ChangePasswordAtLogon $true')
        Mitre = 'T1558'
    }

    # Zaufania bez jawnie włączonego AES
    $trustObjs = @(Find-Ldap -SearchBase "CN=System,$($domain.DistinguishedName)" -Filter '(objectClass=trustedDomain)' -Properties 'msDS-SupportedEncryptionTypes', trustPartner)
    Add-IfAny @{
        Id = 'D-KRB-TRUST'; Category = $catKrb; Severity = 'Medium'
        Title = 'Relacje zaufania bez włączonego szyfrowania AES'
        Objects = ($trustObjs | Where-Object { -not ([int64]$_.'msDS-SupportedEncryptionTypes' -band 0x18) } |
                   ForEach-Object { [pscustomobject]@{ Zaufanie = $_.trustPartner; Szyfrowanie = (Format-EncTypes $_.'msDS-SupportedEncryptionTypes') } })
        Description = 'Bilety między domenami w tych relacjach mogą być szyfrowane RC4, które jest znacznie słabsze od AES i jest wycofywane przez Microsoft.'
        Recommendation = 'Włączyć AES na relacji zaufania po obu stronach (w konsoli Active Directory Domains and Trusts: "The other domain supports Kerberos AES Encryption").'
        Fix = (Fx 'ksetup /setenctypeattr <domena_zaufana> AES128-CTS-HMAC-SHA1-96 AES256-CTS-HMAC-SHA1-96   # na DC, po obu stronach')
        Mitre = 'T1558'
    }

    $show = { $_ | Select-Object -Property * -ExcludeProperty Kod }
    Add-IfAny @{
        Id = 'DC-KRB-DES-USED'; Category = $catKrb; Severity = 'High'
        Title = "Bilety Kerberos szyfrowane DES wydane w ostatnich $krbEventDays dniach"
        Objects = ($usage | Where-Object { $_.Kod -in '0x1', '0x3' } | ForEach-Object $show)
        Description = 'Kontrolery domeny faktycznie wydają bilety szyfrowane DES (zdarzenia 4768/4769). Wskazane konta/usługi i adresy klientów pokazują, który system lub aplikacja wymaga DES.'
        Recommendation = 'Zidentyfikować systemy z kolumny AdresKlienta i usługi z kolumny Usluga, zaktualizować je lub skonfigurować AES, następnie usunąć DES z konfiguracji kont (D-KRB-DES).'
        Fix = (Fx '# na DC: Get-WinEvent -LogName Security -FilterXPath "*[EventData[Data[@Name=''TicketEncryptionType'']=''0x3'']]" -MaxEvents 50')
        Mitre = 'T1558'
    }
    Add-IfAny @{
        Id = 'DC-KRB-RC4-USED'; Category = $catKrb; Severity = 'Medium'
        Title = "Bilety Kerberos szyfrowane RC4 wydane w ostatnich $krbEventDays dniach"
        Objects = ($usage | Where-Object { $_.Kod -in '0x17', '0x18' } | Sort-Object Bilety -Descending | ForEach-Object $show)
        Description = 'Bilety RC4 dla kont usług (4769) można łamać offline wielokrotnie szybciej niż AES (Kerberoasting). Microsoft wycofuje RC4 w Kerberos; lista pokazuje, co trzeba przygotować przed wyłączeniem RC4.'
        Recommendation = 'Dla kont usług ustawić AES (msDS-SupportedEncryptionTypes = AES128+AES256) i zmienić hasło; sprawdzić stare systemy i urządzenia z kolumny AdresKlienta. Docelowo wyłączyć RC4 na DC (GPO: Network security: Configure encryption types allowed for Kerberos).'
        Fix = (Fx 'Set-ADUser -Identity <konto_uslugi> -KerberosEncryptionType AES128,AES256', 'Set-ADAccountPassword -Identity <konto_uslugi> -Reset   # klucze AES powstają przy zmianie hasła')
        Mitre = 'T1558.003'
    }
    Add-IfAny @{
        Id = 'DC-KRB-UNKNOWN'; Category = 'Błędy testów'; Severity = 'Info'; Title = 'Nie odczytano użycia szyfrowania Kerberos z DC'; Objects = $krbUnk
        Description = 'Odczyt dziennika Security lub rejestru KDC przez WinRM nie powiódł się (brak WinRM lub uprawnień).'
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
    if ("$($forest.ForestMode)" -notmatch '2016|2025') {
        Add-Finding @{
            Id = 'D-FFL'; Category = $catDom; Severity = 'Low'
            Title = "Poziom funkcjonalny lasu: $($forest.ForestMode)"
            Description = 'Poziom funkcjonalny lasu wyznacza najstarszą dopuszczalną wersję DC we wszystkich domenach lasu i blokuje funkcje całego lasu: Kosz AD wymaga co najmniej 2008 R2, uprzywilejowany dostęp czasowy (PAM) - 2016. Niski poziom oznacza zwykle, że w lesie są lub były stare DC.'
            Recommendation = 'Po wycofaniu starszych DC we wszystkich domenach lasu podnieść poziom funkcjonalny domen, a następnie lasu do Windows2016. Operacja jest praktycznie nieodwracalna - wcześniej potwierdzić, że nie ma DC ze starszym systemem.'
            Fix = (Fx 'Get-ADForest | Select-Object ForestMode, Domains', 'Get-ADDomainController -Filter * | Select-Object HostName, OperatingSystem', 'Set-ADForestMode -Identity {LAS} -ForestMode Windows2016Forest')
        }
    }

    # Pre-Windows 2000 Compatible Access (S-1-5-32-554): szerokie podmioty jako członkowie (FSP: CN=S-1-5-11,CN=ForeignSecurityPrincipals,...)
    $wide = @{ 'S-1-1-0' = 'Everyone (Wszyscy)'; 'S-1-5-7' = 'Anonymous Logon'; 'S-1-5-11' = 'Authenticated Users' }
    $pw   = Get-LdapObject -Identity 'S-1-5-32-554' -Properties member
    $pwHits = @(@($pw.member) | ForEach-Object { if ("$_" -match '^CN=(S-1-[\d-]+),') { $Matches[1] } } | Where-Object { $wide.ContainsKey($_) })
    if ($pwHits.Count) {
        $anon = @($pwHits | Where-Object { $_ -ne 'S-1-5-11' }).Count -gt 0
        Add-Finding @{
            Id = 'D-PREWIN2000'; Category = $catDom; Severity = $(if ($anon) { 'High' } else { 'Low' })
            Title = "Pre-Windows 2000 Compatible Access zawiera: $(($pwHits | ForEach-Object { $wide[$_] }) -join ', ')"
            Objects = ($pwHits | ForEach-Object { [pscustomobject]@{ Czlonek = $wide[$_]; SID = $_ } })
            Description = 'Grupa Pre-Windows 2000 Compatible Access ma prawo odczytu atrybutów i członkostwa większości użytkowników i grup. Everyone lub Anonymous Logon w grupie pozwala wyliczyć konta i grupy domeny bez logowania (anonimowe zapytania SAMR/LDAP), co ułatwia zgadywanie haseł. Authenticated Users to ustawienie domyślne domen zakładanych w trybie zgodności; daje każdemu kontu, także komputera, szerszy odczyt niż potrzebny.'
            Recommendation = 'Usunąć Everyone i Anonymous Logon. Authenticated Users usunąć po teście zgodności (systemy NT4/Samba, starsze urządzenia i aplikacje wyliczające użytkowników). Zmiana działa po wygaśnięciu tokenów (wylogowanie, restart usług).'
            Fix = (Fx '([ADSI]''LDAP://<SID=S-1-5-32-554>'').Remove(''LDAP://<SID=S-1-5-7>'')   # Anonymous Logon',
                      '([ADSI]''LDAP://<SID=S-1-5-32-554>'').Remove(''LDAP://<SID=S-1-1-0>'')   # Everyone',
                      '([ADSI]''LDAP://<SID=S-1-5-32-554>'').Remove(''LDAP://<SID=S-1-5-11>'')  # Authenticated Users - po teście')
            Mitre = 'T1087.002'
        }
    }

    # dSHeuristics: 7 = operacje anonimowe LDAP, 28/29 = poprawki CVE-2021-42291 (KB5008383); '1' w 28/29 wyłącza ochronę
    $dsh = "$((Get-LdapObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,$configDn" -Properties dSHeuristics).dsheuristics)"
    $dshRows = @(
        if ((Get-DsHeuristicsChar $dsh 7) -eq '2') { [pscustomobject]@{ Znak = 7; Nazwa = 'fLDAPBlockAnonOps'; Wartosc = '2'; Skutek = 'anonimowe operacje LDAP dozwolone'; S = 'High' } }
        if ((Get-DsHeuristicsChar $dsh 28) -eq '1') { [pscustomobject]@{ Znak = 28; Nazwa = 'AttributeAuthorizationOnLDAPAdd'; Wartosc = '1'; Skutek = 'wyłączona dodatkowa kontrola atrybutów przy tworzeniu obiektów (CVE-2021-42291)'; S = 'Medium' } }
        if ((Get-DsHeuristicsChar $dsh 29) -eq '1') { [pscustomobject]@{ Znak = 29; Nazwa = 'BlockOwnerImplicitRights'; Wartosc = '1'; Skutek = 'wyłączona blokada niejawnych praw właściciela (CVE-2021-42291)'; S = 'Medium' } }
    )
    if ($dshRows.Count) {
        Add-Finding @{
            Id = 'D-DSHEURISTICS'; Category = $catDom; Severity = $(if ($dshRows.S -contains 'High') { 'High' } else { 'Medium' })
            Title = "dSHeuristics osłabia zabezpieczenia lasu (wartość: $dsh)"
            Objects = ($dshRows | Select-Object Znak, Nazwa, Wartosc, Skutek)
            Description = 'Atrybut dSHeuristics zmienia zachowanie AD w całym lesie. Siódmy znak "2" pozwala na anonimowe zapytania LDAP (wyliczanie kont bez logowania, o ile pozwalają na to uprawnienia). Znaki 28 i 29 ustawione na "1" wyłączają poprawki CVE-2021-42291, które utrudniają przejęcie domeny przez konta komputerów tworzone przez zwykłych użytkowników.'
            Recommendation = 'Przywrócić znaki do "0" (wartość domyślna). Wcześniej ustalić, kto i po co je zmienił (np. stara aplikacja wymagająca anonimowego LDAP).'
            Fix = (Fx '$ds = [ADSI]"LDAP://CN=Directory Service,CN=Windows NT,CN=Services,$(([ADSI]''LDAP://RootDSE'').configurationNamingContext)"',
                      '$ds.dSHeuristics   # bieżąca wartość; zmiana przez ADSI Edit po uzgodnieniu z klientem')
            Mitre = 'T1087.002'
        }
    }

    # Strefy DNS w AD: CreateChild dla Authenticated Users/Everyone (domyślne - potrzebne do dynamicznej rejestracji) bez rekordu wildcard
    $wideDns = @{ 'S-1-5-11' = 'Authenticated Users'; 'S-1-1-0' = 'Everyone'; 'S-1-5-7' = 'Anonymous Logon' }
    $dnsRows = foreach ($base in @("CN=MicrosoftDNS,DC=DomainDnsZones,$domainDn", "CN=MicrosoftDNS,DC=ForestDnsZones,$($rootDse.rootDomainNamingContext)", "CN=MicrosoftDNS,CN=System,$domainDn")) {
        $zones = @()
        try { $zones = @(Find-Ldap -SearchBase $base -Scope OneLevel -Filter '(objectClass=dnsZone)' -Properties nTSecurityDescriptor -SecurityDescriptor) } catch { $zones = @() }
        foreach ($z in $zones) {
            if ($z.name -in 'RootDNSServers', '..TrustAnchors' -or $z.ntsecuritydescriptor -isnot [System.DirectoryServices.ActiveDirectorySecurity]) { continue }
            $who = @($z.ntsecuritydescriptor.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) |
                     Where-Object { $_.AccessControlType -eq 'Allow' -and ($_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::CreateChild) -and $wideDns.ContainsKey($_.IdentityReference.Value) } |
                     ForEach-Object { $wideDns[$_.IdentityReference.Value] } | Sort-Object -Unique)
            if (-not $who.Count) { continue }
            $wild = @()
            try { $wild = @(Find-Ldap -SearchBase $z.distinguishedname -Scope OneLevel -Filter '(name=\2a)') } catch { $wild = @() }
            if (-not $wild.Count) {
                [pscustomobject]@{ Strefa = $z.name; Partycja = (($base -split ',', 2)[1]); Uprawnieni = ($who -join ', '); RekordWildcard = 'brak' }
            }
        }
    }
    Add-IfAny @{
        Id = 'D-DNS-CREATECHILD'; Category = $catDom; Severity = 'Low'
        Title = 'Strefy DNS, w których każdy użytkownik może tworzyć rekordy (bez rekordu wildcard)'
        Objects = $dnsRows
        Description = 'W strefach DNS zintegrowanych z AD każde konto domeny może domyślnie tworzyć nowe rekordy - to jest potrzebne do dynamicznej rejestracji komputerów. Zwykły użytkownik może jednak zarejestrować nieistniejącą nazwę (np. literówkę popularnego serwera) albo rekord wildcard "*" i przechwytywać ruch oraz poświadczenia (ADIDNS spoofing).'
        Recommendation = 'W każdej strefie utworzyć rekord wildcard "*" (np. wskazujący na adres nieużywany lub serwer DNS) albo odebrać Authenticated Users prawo CreateChild, jeśli rejestrację rekordów wykonuje serwer DHCP. Monitorować tworzenie obiektów dnsNode (zdarzenie 5137). Sprawdzić, czy GlobalQueryBlockList zawiera wpad i isatap.'
        Fix = (Fx 'Add-DnsServerResourceRecordA -ZoneName <strefa> -Name ''*'' -IPv4Address <adres> -ComputerName <DC>',
                  'Get-DnsServerGlobalQueryBlockList -ComputerName <DC>')
        Mitre = 'T1557'
    }
    $rb = Get-LdapObject -Identity "CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,$configDn" -Properties 'msDS-EnabledFeatureBL'
    if (-not @($rb.'msds-enabledfeaturebl' | Where-Object { $_ }).Count) {
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
    $dcSess  = [System.Collections.Generic.List[object]]::new()
    $dcAnon  = [System.Collections.Generic.List[object]]::new()

    # NetSessionEnum (poziom 10) zwykłym kontem: 0/234 = lista sesji dostępna (brak NetCease), 5 = odmowa dostępu
    if (-not ('PepixNetApi' -as [type])) {
        try {
            Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class PepixNetApi {
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    static extern int NetSessionEnum(string server, string client, string user, int level, out IntPtr buf, int prefmax, out int read, out int total, ref int resume);
    [DllImport("netapi32.dll")]
    static extern int NetApiBufferFree(IntPtr buf);
    public static int Probe(string server) {
        IntPtr b; int r, t, h = 0;
        int rc = NetSessionEnum(server, null, null, 10, out b, -1, out r, out t, ref h);
        if (b != IntPtr.Zero) NetApiBufferFree(b);
        return rc;
    }
}
'@
        } catch { $dcUnk.Add([pscustomobject]@{ DC = '(wszystkie)'; Test = 'NetSessionEnum'; Metoda = "Add-Type: $($_.Exception.Message)" }) }
    }

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

            # Sondy behawioralne (zwykłe konto, bez zmian na DC) - każda we własnym try, żeby błąd sondy nie przerywał testów DC
            if ($runAsPriv) {
                $dcUnk.Add([pscustomobject]@{ DC = $h; Test = 'NetSessionEnum (DC-NETSESSION)'; Metoda = 'pominięte - przegląd uruchomiony kontem uprzywilejowanym, administrator zawsze widzi sesje' })
            } elseif ('PepixNetApi' -as [type]) {
                try {
                    $rc = [PepixNetApi]::Probe("\\$h")
                    if ($rc -in 0, 234) { $dcSess.Add([pscustomobject]@{ DC = $h; Wynik = 'NetSessionEnum dostępne dla zwykłego konta'; Metoda = 'NetSessionEnum poziom 10' }) }
                    elseif ($rc -ne 5) { $dcUnk.Add([pscustomobject]@{ DC = $h; Test = "NetSessionEnum (kod $rc)"; Metoda = 'NetSessionEnum poziom 10' }) }
                } catch { $dcUnk.Add([pscustomobject]@{ DC = $h; Test = 'NetSessionEnum'; Metoda = $_.Exception.Message }) }
            }
            # Anonimowy LDAP. Uwaga: metody DirectoryEntry wywoływać przez .psbase - adapter PowerShell przy nieudanym
            # powiązaniu próbuje odczytać "Dispose" jako atrybut LDAP i rzuca wyjątek.
            $anonDe = $null; $anonS = $null
            try {
                $anonDe = New-Object System.DirectoryServices.DirectoryEntry ("LDAP://$h/$domainDn", $null, $null, [System.DirectoryServices.AuthenticationTypes]::Anonymous)
                $anonS  = New-Object System.DirectoryServices.DirectorySearcher -ArgumentList $anonDe, '(&(objectCategory=person)(objectClass=user))'
                $anonS.SizeLimit = 1; [void]$anonS.PropertiesToLoad.Add('sAMAccountName')
                $hit = $anonS.FindOne()
                if ($hit) { $dcAnon.Add([pscustomobject]@{ DC = $h; Wynik = "anonimowe zapytanie LDAP zwróciło konto $($hit.Properties['samaccountname'])"; Metoda = 'LDAP bez uwierzytelnienia' }) }
            } catch {
                $null = $_   # oczekiwane: "operations error" = operacje anonimowe zablokowane
            } finally {
                try { if ($anonS) { $anonS.Dispose() } } catch { $null = $_ }
                try { if ($anonDe) { $anonDe.psbase.Dispose() } } catch { $null = $_ }
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
        Id = 'DC-ANONLDAP'; Category = $catDC; Severity = 'High'; Title = 'DC odpowiada na anonimowe zapytania LDAP o konta'; Objects = $dcAnon
        Description = 'Bez logowania można pobrać listę kont i grup domeny (anonimowy LDAP). Atakujący w sieci lokalnej zdobywa w ten sposób nazwy kont do zgadywania haseł i obraz struktury domeny. Zwykle wynika to z dSHeuristics (7. znak = 2) połączonego z uprawnieniami ANONYMOUS LOGON lub Everyone (np. w Pre-Windows 2000 Compatible Access).'
        Recommendation = 'Usunąć 7. znak "2" z dSHeuristics (patrz D-DSHEURISTICS) i usunąć Anonymous Logon / Everyone z Pre-Windows 2000 Compatible Access. Wcześniej ustalić, czy dostępu anonimowego nie używa jakieś urządzenie lub aplikacja (np. stare drukarki, skanery, systemy Unix).'
        Fix = (Fx '# dSHeuristics: CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,... (ADSI Edit) - ustawić 7. znak na 0',
                  '([ADSI]''LDAP://<SID=S-1-5-32-554>'').Remove(''LDAP://<SID=S-1-5-7>'')')
        Mitre = 'T1087.002'
    }
    Add-IfAny @{
        Id = 'DC-NETSESSION'; Category = $catDC; Severity = 'Low'; Title = 'Zwykłe konto może wyliczać sesje SMB na DC (brak NetCease)'; Objects = $dcSess
        Description = 'NetSessionEnum pokazuje, z jakich komputerów zalogowani są użytkownicy - także administratorzy. Narzędzia typu BloodHound używają tego do wskazania stacji, z których najłatwiej przejąć konto administratora domeny.'
        Recommendation = 'Ograniczyć NetSessionEnum do administratorów (zmiana uprawnień SrvsvcSessionInfo, tzw. NetCease) na DC i serwerach, a docelowo na wszystkich komputerach; wymaga restartu usługi Server.'
        Fix = (Fx '# skrypt NetCease.ps1 (Microsoft, PowerShell Gallery) uruchomiony na DC, potem:', 'Restart-Service -Name LanmanServer -Force')
        Mitre = 'T1049'
    }
    Add-IfAny @{
        Id = 'DC-UNKNOWN'; Category = 'Błędy testów'; Severity = 'Info'; Title = 'Testy DC nierozstrzygnięte'; Objects = $dcUnk
        Description = 'Nie udało się ustalić wyniku (brak łączności, zapora lub brak dostępu). Powtórzyć z innej stacji lub z przełącznikiem -UseWinRM.'
    }
}
#endregion

#region ---------- GPO w całej domenie (wszystkie podlinkowane) ----------
# Ustawienia, które powinny obejmować wszystkie komputery, nie tylko DC (te sprawdza CIS). Odczyt Registry.pol i preferencji z SYSVOL.
if (-not $SkipDCChecks) {
    Invoke-Check 'GPO-ALL' {
        $gpoReg = @(Get-LinkedGpoRegistry | Where-Object { -not $_.Deleted })
        $pick = { param([string]$KeyEnd, [string]$Name)
                  @($gpoReg | Where-Object { $_.Key -match ([regex]::Escape($KeyEnd) + '$') -and (-not $Name -or $_.Name -eq $Name) }) }
        $row  = { [pscustomobject]@{ GPO = $_.Gpo; Ustawienie = "$($_.Key)\$($_.Name)"; Wartosc = "$($_.Data)" } }

        $ll = & $pick 'Windows NT\DNSClient' 'EnableMulticast'
        if (-not @($ll | Where-Object { "$($_.Data)" -eq '0' }).Count) {
            Add-Finding @{
                Id = 'D-GPO-LLMNR'; Category = $catDom; Severity = 'Medium'
                Title = 'Żadne podlinkowane GPO nie wyłącza LLMNR'
                Objects = ($ll | ForEach-Object $row)
                Description = 'Gdy nazwy nie da się rozwiązać w DNS (literówka, nieistniejący udział), Windows pyta o nią całą sieć lokalną przez LLMNR (oraz NetBIOS i mDNS). Atakujący w tej samej sieci odpowiada na takie zapytania i przechwytuje skróty NTLMv2 użytkowników (narzędzia typu Responder), które łamie offline albo przekazuje dalej (relay).'
                Recommendation = 'GPO dla wszystkich komputerów: Konfiguracja komputera > Szablony administracyjne > Sieć > Klient DNS > Wyłącz rozpoznawanie nazw multiemisji = Włączone. Dodatkowo wyłączyć NetBIOS over TCP/IP (opcja DHCP 001 dla klientów Microsoft lub ustawienie karty) i mDNS.'
                Fix = (Fx '# GPO: Computer Configuration > Administrative Templates > Network > DNS Client > Turn off multicast name resolution = Enabled',
                          'reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast   # weryfikacja na komputerze')
                Mitre = 'T1557.001'
            }
        }

        $ps = & $pick 'PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
        if (-not @($ps | Where-Object { "$($_.Data)" -eq '1' }).Count) {
            Add-Finding @{
                Id = 'D-GPO-PSLOG'; Category = $catDom; Severity = 'Low'
                Title = 'Żadne podlinkowane GPO nie włącza rejestrowania bloków skryptów PowerShell'
                Objects = ($ps | ForEach-Object $row)
                Description = 'Bez Script Block Logging (zdarzenie 4104) w dziennikach nie ma treści wykonanych poleceń PowerShell, także zaciemnionych i ładowanych z pamięci. PowerShell jest podstawowym narzędziem atakujących po włamaniu, więc brak tych zdarzeń utrudnia wykrycie i analizę incydentu.'
                Recommendation = 'Włączyć Script Block Logging (i opcjonalnie Module Logging) GPO dla wszystkich komputerów, zwiększyć rozmiar dziennika Microsoft-Windows-PowerShell/Operational i przekazywać zdarzenia 4104 do SIEM.'
                Fix = (Fx '# GPO: Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging = Enabled')
                Mitre = 'T1059.001'
            }
        }

        # Hardened UNC Paths: Windows 10+ domyślnie wymaga uwierzytelnienia i integralności dla SYSVOL/NETLOGON; starsze systemy - tylko z GPO
        $hp   = & $pick 'NetworkProvider\HardenedPaths' ''
        $sysv = @($hp | Where-Object { $_.Name -match 'SYSVOL|NETLOGON|^\\\\\*\\?\*?$' })
        $weak = @($sysv | Where-Object { "$($_.Data)" -match '(RequireMutualAuthentication|RequireIntegrity)\s*=\s*0' })
        $legacy = 0
        foreach ($o in $invOs) { if ("$($o.System)" -match 'Windows (7|8|Vista|XP)|Server.*(2003|2008|2012)') { $legacy += [int]$o.Komputery } }
        if ($weak.Count -or (-not $sysv.Count -and $legacy -gt 0)) {
            Add-Finding @{
                Id = 'D-GPO-HARDPATH'; Category = $catDom; Severity = $(if ($weak.Count) { 'Medium' } else { 'Low' })
                Title = $(if ($weak.Count) { 'GPO osłabia ochronę ścieżek SYSVOL/NETLOGON (Hardened UNC Paths)' } else { "Brak Hardened UNC Paths dla SYSVOL/NETLOGON przy $legacy kontach komputerów ze starszym Windows" })
                Objects = ($(if ($weak.Count) { $weak } else { $hp }) | ForEach-Object $row)
                Description = 'Komputery pobierają GPO i skrypty logowania z SYSVOL i NETLOGON. Bez wymogu wzajemnego uwierzytelnienia i integralności atakujący w sieci może podsunąć własne zasady lub skrypty (MS15-011, MS15-014) i uruchomić kod z uprawnieniami SYSTEM. Windows 10/11 i Server 2016+ chronią te ścieżki domyślnie, o ile GPO tego nie wyłącza; Windows 7/8.1 i Server 2008/2012 wymagają ustawienia z GPO.'
                Recommendation = 'Usunąć wartości RequireMutualAuthentication=0 / RequireIntegrity=0 z GPO. Dla starszych systemów ustawić Hardened UNC Paths: \\*\SYSVOL i \\*\NETLOGON = RequireMutualAuthentication=1, RequireIntegrity=1.'
                Fix = (Fx '# GPO: Computer Configuration > Administrative Templates > Network > Network Provider > Hardened UNC Paths',
                          '#   \\*\SYSVOL   = RequireMutualAuthentication=1, RequireIntegrity=1',
                          '#   \\*\NETLOGON = RequireMutualAuthentication=1, RequireIntegrity=1')
                Mitre = 'T1557'
            }
        }
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

#region ---------- aktualizacje kontrolerów domeny ----------
# Poziom poprawek = UBR (numer po kropce, np. 20348.5761). Zwykłe konto: zdalny rejestr - ścieżka SOFTWARE\Microsoft\Windows NT\CurrentVersion
# jest domyślnie na liście AllowedExactPaths, więc czyta ją każdy użytkownik domeny (wymaga działającej usługi Remote Registry).
# -UseWinRM dodatkowo: ostatnia zainstalowana poprawka, ostatni restart, oczekujący restart, źródło aktualizacji (WSUS).
# AKTUALIZOWAĆ CO MIESIĄC: UBR z ostatniej comiesięcznej aktualizacji zabezpieczeń (Patch Tuesday) i jej data.
$patchRefDate = [datetime]'2026-10-13'
$patchRef     = @{ 14393 = 9612; 17763 = 9376; 20348 = 5761; 26100 = 33650 }   # Server 2016 / 2019 / 2022 / 2025
$invPatch     = [System.Collections.Generic.List[object]]::new()
if (-not $SkipDCChecks) {
    Invoke-Check 'DC-PATCH' {
        foreach ($dc in $dcs) {
            $h = $dc.HostName
            $build = 0; if ("$($dc.OperatingSystemVersion)" -match '\((\d+)\)') { $build = [int]$Matches[1] }
            $ubr = $null; $err = ''; $win = $null
            try {
                $base = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $h)
                $k = $base.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion')
                if ($k) {
                    $ubr = $k.GetValue('UBR')
                    $cb  = $k.GetValue('CurrentBuildNumber'); if ($cb) { $build = [int]$cb }
                    $k.Close()
                }
                $base.Close()
            } catch { $err = "zdalny rejestr: $((Get-InnerException $_.Exception).Message)" }

            if ($UseWinRM) {
                try {
                    $win = Invoke-Command -ComputerName $h -ErrorAction Stop -ScriptBlock {
                        $os = Get-CimInstance Win32_OperatingSystem -Verbose:$false
                        $hf = Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1
                        $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
                        $pend = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
                                (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
                        $wu = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction SilentlyContinue
                        [pscustomobject]@{ UBR = $cv.UBR; Build = $cv.CurrentBuildNumber; LastBoot = $os.LastBootUpTime
                                           LastHotfix = $hf.InstalledOn; LastKB = $hf.HotFixID; Pending = $pend; WSUS = $wu.WUServer }
                    }
                    if ($null -eq $ubr) { $ubr = $win.UBR; $build = [int]$win.Build }
                } catch { $err = (@($err, "WinRM: $($_.Exception.Message)") | Where-Object { $_ }) -join '; ' }
            }

            $ref  = if ($patchRef.ContainsKey($build)) { $patchRef[$build] } else { $null }
            $stan = if ($null -eq $ubr) { 'nieznany' }
                    elseif ($null -eq $ref) { 'brak wzorca dla tej wersji' }
                    elseif ([int]$ubr -ge $ref) { 'aktualny' }
                    else { 'nieaktualny' }
            if ($stan -ne 'nieaktualny' -and $win -and $win.LastHotfix -and $win.LastHotfix -lt $now.AddDays(-60)) { $stan = 'ostatnia poprawka > 60 dni' }

            $row = [pscustomobject]@{
                DC                 = $h
                System             = $dc.OperatingSystem
                Wersja             = $(if ($null -ne $ubr) { "$build.$ubr" } else { "$build.?" })
                Wzorzec            = $(if ($ref) { "$build.$ref ($(Format-Date $patchRefDate))" } else { '' })
                Stan               = $stan
                OstatniaPoprawka   = $(if ($win -and $win.LastHotfix) { "$(Format-Date $win.LastHotfix) $($win.LastKB)" } else { '' })
                OstatniRestart     = $(if ($win) { Format-Date $win.LastBoot } else { '' })
                OczekujeRestartu   = $(if ($win) { if ($win.Pending) { 'Tak' } else { 'Nie' } } else { '' })
                ZrodloAktualizacji = $(if ($win) { if ($win.WSUS) { "WSUS: $($win.WSUS)" } else { 'Windows Update (brak polityki WSUS)' } } else { '' })
                Blad               = $err
                Build              = $build
                Ubr                = $ubr
                Boot               = $(if ($win) { $win.LastBoot } else { $null })
                Pending            = $(if ($win) { [bool]$win.Pending } else { $false })
            }
            $invPatch.Add($row)
        }

        $show = { $_ | Select-Object -Property * -ExcludeProperty Build, Ubr, Boot, Pending }
        $refNote = if (($now - $patchRefDate).TotalDays -gt 40) { " Uwaga: wzorzec poprawek w skrypcie pochodzi z $(Format-Date $patchRefDate) i może być nieaktualny - DC może być starszy, niż wskazuje ten test." } else { '' }

        Add-IfAny @{
            Id = 'DC-PATCH-OLD'; Category = $catDC; Severity = 'High'
            Title = 'Kontrolery domeny bez aktualnych poprawek zabezpieczeń'
            Objects = ($invPatch | Where-Object { $_.Stan -in 'nieaktualny', 'ostatnia poprawka > 60 dni' } | ForEach-Object $show)
            Description = "Poziom poprawek DC (kolumna Wersja) jest niższy niż comiesięczna aktualizacja zabezpieczeń z $(Format-Date $patchRefDate) (kolumna Wzorzec) albo ostatnia poprawka została zainstalowana ponad 60 dni temu. Niezałatane DC są głównym celem ataków (np. podatności Kerberos, Netlogon, LDAP, Print Spooler).$refNote"
            Recommendation = 'Zainstalować najnowszą aktualizację zbiorczą na wszystkich DC (po jednym, przy zdrowej replikacji, z restartem). Ustalić stały cykl aktualizacji DC - np. w ciągu 14 dni od Patch Tuesday - i monitorować jego wykonanie.'
            Fix = (Fx 'Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5   # na DC', '# Windows Update / WSUS: zatwierdzić i zainstalować najnowszą aktualizację zbiorczą (LCU) wraz z SSU', 'repadmin /replsummary   # przed i po restarcie każdego DC')
            Mitre = 'T1210'
        }

        # Różny poziom poprawek DC z tym samym systemem - przydatne, gdy brak wzorca albo wzorzec jest stary
        $maxUbr = @{}
        foreach ($r in @($invPatch | Where-Object { $null -ne $_.Ubr })) {
            if (-not $maxUbr.ContainsKey($r.Build) -or [int]$r.Ubr -gt $maxUbr[$r.Build]) { $maxUbr[$r.Build] = [int]$r.Ubr }
        }
        Add-IfAny @{
            Id = 'DC-PATCH-DIFF'; Category = $catDC; Severity = 'Medium'
            Title = 'Kontrolery domeny z tym samym systemem na różnym poziomie poprawek'
            Objects = ($invPatch | Where-Object { $null -ne $_.Ubr -and $_.Stan -notin 'nieaktualny', 'ostatnia poprawka > 60 dni' -and [int]$_.Ubr -lt $maxUbr[$_.Build] } | ForEach-Object $show)
            Description = 'Część DC ma starsze poprawki niż pozostałe DC z tym samym systemem. Oznacza to, że proces aktualizacji nie obejmuje wszystkich kontrolerów domeny.'
            Recommendation = 'Ujednolicić poziom poprawek; sprawdzić, dlaczego dany DC nie otrzymuje aktualizacji (grupa WSUS, okno serwisowe, błędy instalacji).'
            Fix = (Fx 'Get-WinEvent -LogName ''Microsoft-Windows-WindowsUpdateClient/Operational'' -MaxEvents 20   # na DC')
            Mitre = 'T1210'
        }
        Add-IfAny @{
            Id = 'DC-REBOOT'; Category = $catDC; Severity = 'Medium'
            Title = 'Kontrolery domeny oczekujące na restart lub bez restartu ponad 60 dni'
            Objects = ($invPatch | Where-Object { $_.Pending -or ($_.Boot -and $_.Boot -lt $now.AddDays(-60)) } | ForEach-Object $show)
            Description = 'Zainstalowane aktualizacje zbiorcze zaczynają działać dopiero po restarcie. DC oczekujący na restart lub działający bez restartu od miesięcy jest w praktyce niezałatany.'
            Recommendation = 'Zaplanować restart DC w oknie serwisowym (po jednym, przy zdrowej replikacji).'
            Fix = (Fx 'Restart-Computer -ComputerName <DC>   # w oknie serwisowym, po jednym DC')
            Mitre = 'T1210'
        }
        Add-IfAny @{
            Id = 'DC-PATCH-UNKNOWN'; Category = 'Błędy testów'; Severity = 'Info'
            Title = 'Nie ustalono poziomu poprawek DC'
            Objects = ($invPatch | Where-Object { $_.Stan -eq 'nieznany' } | ForEach-Object { [pscustomobject]@{ DC = $_.DC; Blad = $_.Blad } })
            Description = 'Odczyt zdalnego rejestru nie powiódł się - zwykle zatrzymana usługa Remote Registry na DC lub zapora. Powtórzyć z przełącznikiem -UseWinRM.'
        }
    }
}
#endregion

#region ---------- kondycja domeny i replikacja ----------
# Wszystko zwykłym kontem: metadane replikacji przez LDAP z każdego DC, SYSVOL przez SMB, czas przez NTP (w32tm), DNS przez resolver stacji.
$healthUnk = [System.Collections.Generic.List[object]]::new()
$replErr = @{
    5 = 'odmowa dostępu'; 1256 = 'system zdalny niedostępny'; 1396 = 'błąd logowania (SPN / konto komputera partnera)'
    1722 = 'serwer RPC niedostępny (sieć, zapora, DC wyłączony)'; 1727 = 'zdalne wywołanie procedury nie powiodło się'
    1908 = 'nie znaleziono kontrolera domeny'; 8453 = 'odmowa dostępu do replikacji'; 8456 = 'źródłowy DC odrzuca replikację'
    8457 = 'docelowy DC odrzuca replikację'; 8524 = 'błąd DNS - nie można rozwiązać nazwy partnera'
    8606 = 'obiekty zalegające (lingering objects)'; 8614 = 'przekroczony tombstone lifetime - DC odcięty zbyt długo'
}

Invoke-Check 'REPL' {
    $tsl = (Get-LdapObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,$configDn" -Properties tombstoneLifetime).tombstonelifetime
    if (-not $tsl) { $tsl = 60 }
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($dc in $dcs) {
        try {
            foreach ($m in @(Get-LdapReplPartners -Dc $dc.HostName)) {
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
    $last = Get-LdapAttrChangeTime -Dn $domain.DistinguishedName -Attribute 'dSASignature'
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
                      -not (Find-Ldap -SearchBase $_.ComputerObjectDN -Filter '(&(objectClass=msDFSR-Subscription)(name=SYSVOL Subscription))')
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
            $owner = (Get-LdapObject -Identity $r.Value -Properties fSMORoleOwner).fsmoroleowner
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

# Spójność rejestracji DC: konto komputera (primaryGroupID 516/521, flaga SERVER_TRUST_ACCOUNT / PARTIAL_SECRETS_ACCOUNT,
# OU Domain Controllers) a obiekt serwera i NTDS Settings w CN=Sites. Pozostałość po DC usuniętym bez degradacji.
Invoke-Check 'DC-REG' {
    $p = 'primaryGroupID', 'serverReferenceBL', 'dNSHostName', 'operatingSystem'
    $all = @{}
    foreach ($c in @(Find-Ldap -Properties $p -Filter ('(&(objectCategory=computer)(|(primaryGroupID=516)(primaryGroupID=521)' +
                     '(userAccountControl:1.2.840.113556.1.4.803:=8192)(userAccountControl:1.2.840.113556.1.4.803:=67108864)))')) +
                   @(Find-Ldap -SearchBase $domain.DomainControllersContainer -Properties $p -Filter '(objectCategory=computer)')) {
        $all[$c.distinguishedname] = $c
    }
    $rows = foreach ($c in $all.Values) {
        $pg  = [int]$c.primarygroupid; $uac = [int]$c.useraccountcontrol
        $problems = [System.Collections.Generic.List[string]]::new()
        $flag  = [bool]($uac -band 0x2000) -or [bool]($uac -band 0x4000000)
        $group = $pg -in 516, 521
        if (-not $flag -and -not $group) {
            $srvDn = @($c.serverreferencebl | Where-Object { $_ -like "*,CN=Sites,$configDn" })[0]
            $problems.Add($(if ($srvDn) { "konto bez flagi DC w OU Domain Controllers, z pozostałym obiektem serwera w lokacjach ($srvDn) - prawdopodobnie DC zdegradowany bez usunięcia metadanych" }
                            elseif ("$($c.operatingsystem)" -match 'Server') { 'konto bez flagi DC w OU Domain Controllers - prawdopodobnie pozostałość po zdegradowanym DC (obejmują je zasady GPO dla DC)' }
                            else { 'zwykły komputer w OU Domain Controllers (obejmują go zasady GPO dla DC)' }))
        } else {
            if ($flag -ne $group) { $problems.Add("niespójne konto: primaryGroupID $pg, flaga DC $(if ($flag) { 'tak' } else { 'nie' })") }
            $srvDn = @($c.serverreferencebl | Where-Object { $_ -like "*,CN=Sites,$configDn" })[0]
            if (-not $srvDn) {
                $problems.Add('brak obiektu serwera w lokacjach (CN=Sites)')
            } else {
                $ntds = $null
                try { $ntds = Get-LdapObject -Identity "CN=NTDS Settings,$srvDn" } catch { $ntds = $null }
                if (-not $ntds) { $problems.Add('brak NTDS Settings - DC zdegradowany lub usunięty niepoprawnie') }
            }
            if (-not $c.Enabled) { $problems.Add('konto wyłączone') }
        }
        if ($problems.Count) {
            ConvertTo-ComputerRow $c | Add-Member -NotePropertyName Problem -NotePropertyValue ($problems -join '; ') -PassThru
        }
    }
    Add-IfAny @{
        Id = 'DC-REGISTRATION'; Category = $catHealth; Severity = 'Medium'
        Title = 'Konta kontrolerów domeny bez kompletnej rejestracji w lesie'
        Objects = $rows
        Description = 'Konto komputera wygląda na kontroler domeny (grupa podstawowa, flaga konta lub OU Domain Controllers), ale jego rejestracja w konfiguracji lasu jest niepełna albo niespójna. Zwykle to pozostałość po DC wyłączonym bez degradacji lub zdegradowanym z błędem. Konto z flagą DC ma uprawnienia kontrolera domeny (m.in. replikację haseł - DCSync), więc jest zbędnym celem ataku; klienci i aplikacje mogą też próbować łączyć się z nieistniejącym DC.'
        Recommendation = 'Ustalić, czy serwer istnieje. Jeśli nie - usunąć jego metadane (Usługi i lokacje AD albo ntdsutil "metadata cleanup"), konto komputera i rekordy DNS (_msdcs, _ldap, _kerberos). Zwykłe serwery przenieść z OU Domain Controllers.'
        Fix = (Fx 'Get-ADComputer <DC> -Properties PrimaryGroupID, UserAccountControl, ServerReferenceBL',
                  'ntdsutil "metadata cleanup" "remove selected server <DN serwera>" quit quit   # tylko gdy serwer na pewno nie istnieje',
                  'Remove-ADComputer -Identity <DC>')
        Mitre = 'T1003.006'
    }
}

# Adresy DC a podsieci AD (CN=Subnets,CN=Sites): brak podsieci lub podsieć innej lokacji
Invoke-Check 'SITES' {
    $subnets = @(Find-Ldap -SearchBase "CN=Subnets,CN=Sites,$configDn" -Filter '(objectClass=subnet)' -Properties siteObject)
    $siteOf  = { param($Dn) if ($Dn) { (("$Dn" -split '(?<!\\),')[0]) -replace '^CN=', '' } else { '' } }
    $rows = foreach ($dc in $dcs) {
        if (-not $dc.IPv4Address) { continue }   # nierozwiązywalny DC - patrz DC-PORTS
        $best = @($subnets | Where-Object { Test-IpInSubnet $dc.IPv4Address $_.name } |
                  Sort-Object { [int](($_.name -split '/')[1]) } -Descending)[0]
        $problem = if (-not $subnets.Count) { 'w AD nie zdefiniowano żadnej podsieci' }
                   elseif (-not $best) { 'adres poza wszystkimi podsieciami AD' }
                   elseif (-not $best.siteobject) { "podsieć $($best.name) bez przypisanej lokacji" }
                   elseif ($dc.Site -and (& $siteOf $best.siteobject) -ne $dc.Site) { "podsieć $($best.name) należy do lokacji $(& $siteOf $best.siteobject)" }
        if ($problem) { [pscustomobject]@{ DC = $dc.HostName; Adres = $dc.IPv4Address; LokacjaDC = $dc.Site; Problem = $problem } }
    }
    $siteCount = @(Find-Ldap -SearchBase "CN=Sites,$configDn" -Scope OneLevel -Filter '(objectClass=site)').Count
    $impact = if ($siteCount -le 1) { "Domena ma jedną lokację ($siteCount), więc wpływ na wybór DC jest dziś niewielki; podsieci będą potrzebne po dodaniu drugiej lokacji (oddział, DC w chmurze), a ich brak zaśmieca dziennik NETLOGON." }
              else { "Domena ma $siteCount lokacje/lokacji - klienci mogą uwierzytelniać się do odległego DC przez łącza WAN." }
    Add-IfAny @{
        Id = 'DC-SUBNET'; Category = $catHealth; Severity = 'Low'
        Title = $(if (-not $subnets.Count) { 'W AD nie zdefiniowano podsieci - adresy DC nie są przypisane do lokacji' } else { 'Kontrolery domeny poza podsieciami AD swojej lokacji' })
        Objects = $rows
        Description = "Lokacje i podsieci AD decydują, z którym DC łączą się komputery i jak przebiega replikacja. Gdy adresu DC (lub klienta) nie ma w żadnej podsieci albo podsieć wskazuje inną lokację, Windows nie wie, który DC jest najbliższy, a DC rejestrują zdarzenia NETLOGON 5807. $impact Zdefiniowanych podsieci: $($subnets.Count). Adres DC ustalony przez DNS ze stacji uruchamiającej przegląd."
        Recommendation = 'Dodać podsieci wszystkich segmentów sieci (także serwerowych i VPN) i przypisać je do właściwych lokacji. Adresy klientów spoza podsieci są w pliku %SystemRoot%\debug\netlogon.log na DC (NO_CLIENT_SITE).'
        Fix = (Fx 'New-ADReplicationSubnet -Name ''<adres/maska>'' -Site ''<lokacja>''',
                  'Select-String -Path \\<DC>\admin$\debug\netlogon.log -Pattern NO_CLIENT_SITE | Select-Object -Last 20')
    }
}

Invoke-Check 'DC-MACHINEPWD' {
    Add-IfAny @{
        Id = 'DC-MACHINEPWD'; Category = $catHealth; Severity = 'Medium'
        Title = 'Kontrolery domeny z hasłem konta komputera starszym niż 45 dni'
        Objects = ($dcs | ForEach-Object {
            $c = Get-LdapObject -Identity $_.ComputerObjectDN
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
        $gpos = @(Find-Ldap -SearchBase "CN=Policies,CN=System,$($domain.DistinguishedName)" -Scope OneLevel `
                  -Filter '(objectClass=groupPolicyContainer)' -Properties displayName, versionNumber)
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

# Wynik w czterech obszarach ryzyka (0-100, suma punktów znalezisk obszaru, z limitem 100); wynik ogólny = najgorszy obszar
$areaScore = [ordered]@{}
foreach ($k in $areaNames.Keys) {
    $n = $areaNames[$k]
    $areaScore[$n] = [Math]::Min(100, [int](($real | Where-Object Obszar -eq $n | ForEach-Object { $weights[$_.Severity] } | Measure-Object -Sum).Sum))
}
$score    = [int](($areaScore.Values | Measure-Object -Maximum).Maximum)
# Poziom dojrzałości 1-5: najniższy poziom wśród znalezisk (Critical = 1 ... Low = 4); brak znalezisk = 5
$maturity = if ($real.Count) { [int](($real | ForEach-Object { $_.Poziom } | Measure-Object -Minimum).Minimum) } else { 5 }
$maturityTxt = @{ 1 = 'krytyczne luki - natychmiastowe działania'; 2 = 'poważne luki - pilny plan naprawy'; 3 = 'podstawowe zabezpieczenia - wymagane usprawnienia'
                  4 = 'dobry poziom - drobne usprawnienia'; 5 = 'brak wykrytych problemów w zakresie testów' }

# Status każdej reguły z katalogu (lista sprawdzonych reguł w raporcie)
$errChecks = @($findings | Where-Object { $_.Id -like 'ERR-*' } | ForEach-Object { $_.Id.Substring(4) })
$probeErr  = ($errChecks -contains 'DC-GPO') -or (@($dcs | Where-Object { $errChecks -contains "DC-$($_.Name)" }).Count -gt 0)
$foundIds  = @($real | ForEach-Object { $_.Id })
$ruleStatus = @(foreach ($r in $ruleCatalog) {
    $f  = $real | Where-Object Id -eq $r.Id | Select-Object -First 1
    $st = if ($f) { 'Znalezisko' }
          elseif ($r.W -and $SkipDCChecks) { 'Pominięty (-SkipDCChecks)' }
          elseif ($r.W -eq 'WinRM' -and -not $UseWinRM) { 'Wymaga -UseWinRM' }
          elseif (($errChecks -contains $r.C) -or ($r.C -eq 'DC-PROBE' -and $probeErr)) { 'Błąd testu' }
          elseif ($r.Id -eq 'DC-NETSESSION' -and $runAsPriv) { 'Pominięty (konto uprzywilejowane)' }
          elseif ($r.N -and ($foundIds -contains $r.N)) { 'Nie dotyczy' }
          else { 'Zaliczony' }
    [pscustomobject]@{
        Id = $r.Id; Obszar = $areaNames[$r.O]; Model = $r.M; Test = $r.T; Status = $st
        Waga = $(if ($f) { $f.Severity } else { '' }); Punkty = $(if ($f) { $weights[$f.Severity] } else { 0 })
    }
})

# Macierz ryzyka: obszar x model, punkty znalezisk
$matrix = @(foreach ($k in $areaNames.Keys) {
    $n = $areaNames[$k]
    $models = @($ruleCatalog | Where-Object { $_.O -eq $k } | ForEach-Object { $_.M } | Select-Object -Unique)
    if (@($real | Where-Object { $_.Obszar -eq $n -and $_.Model -eq 'Inne' }).Count) { $models += 'Inne' }
    foreach ($m in $models) {
        $g = @($real | Where-Object { $_.Obszar -eq $n -and $_.Model -eq $m })
        [pscustomobject]@{ Obszar = $n; Model = $m; Znaleziska = $g.Count
                           Punkty = [int](($g | ForEach-Object { $weights[$_.Severity] } | Measure-Object -Sum).Sum) }
    }
})

# Zestawienie zgodności: dla każdego środka NIS2 / zabezpieczenia ISO - liczba testów AD, znaleziska i punkty
function Get-ComplianceRows($Names, [string]$Key) {
    $prop = if ($Key -eq 'N') { 'NIS2' } else { 'ISO27001' }
    foreach ($c in $Names.Keys) {
        $tests = @($ruleCatalog | Where-Object { $m = $complianceMap[$_.M]; $m -and (($m[$Key] -split ',\s*') -contains $c) }).Count
        $g     = @($real | Where-Object { (([string]$_.$prop) -split ',\s*') -contains $c })
        [pscustomobject]@{
            Kod = $c; Nazwa = $Names[$c]; TestyAD = $tests; Znaleziska = $g.Count
            Punkty = [int](($g | ForEach-Object { $weights[$_.Severity] } | Measure-Object -Sum).Sum)
            Ids = @($g | ForEach-Object { $_.Id })
        }
    }
}
$nis2Rows = @(Get-ComplianceRows $nis2Names 'N')
$isoRows  = @(Get-ComplianceRows $isoNames 'I')

# Plan naprawczy: znaleziska w etapach, kolejność wg wagi
# $( ) wokół foreach: instrukcji foreach nie można bezpośrednio przekazać do potoku
$planRows = @($(foreach ($f in $real) {
    $pm   = $planMeta[$f.Id]
    $etap = if ($pm) { [int]$pm[2] } else { 2 }
    if ($f.Severity -eq 'Critical') { $etap = 1 }
    [pscustomobject]@{
        Etap = $etap; Id = $f.Id; Znalezisko = $f.Title; Waga = $f.Severity; Obiekty = $f.Count
        GodzinyMin = $(if ($pm) { [double]$pm[0] } else { $null }); GodzinyMax = $(if ($pm) { [double]$pm[1] } else { $null })
        Uwagi = $(if ($pm) { $pm[3] } else { 'Brak szacunku - do oceny' })
    }
}) | Sort-Object Etap, { $sevOrder[$_.Waga] }, Id)
$planSum = @{}
foreach ($k in 1..3) {
    $g = @($planRows | Where-Object Etap -eq $k)
    $planSum[$k] = @([double](($g | ForEach-Object { $_.GodzinyMin } | Measure-Object -Sum).Sum), [double](($g | ForEach-Object { $_.GodzinyMax } | Measure-Object -Sum).Sum), $g.Count)
}

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
    Obszary   = $areaScore
    Dojrzalosc = $maturity
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

[ordered]@{ Meta = $meta; Podsumowanie = $summary; Porownanie = $diff; Znaleziska = $sorted; Reguly = $ruleStatus
            Zgodnosc = [ordered]@{ NIS2 = $nis2Rows; ISO27001 = $isoRows }; Plan = $planRows
            Inwentaryzacja = [ordered]@{ Domena = $invDomain; DC = $invDCs; GrupyUprzywilejowane = @($invPriv); Zaufania = $invTrusts; Systemy = @($invOs)
                                  AktualizacjeDC = @($invPatch | Select-Object -Property * -ExcludeProperty Build, Ubr, Boot, Pending) } } |
    ConvertTo-Json -Depth 6 | Set-Content "$base.json" -Encoding $encOut

$sorted | Select-Object Id, Obszar, Model, Poziom, NIS2, ISO27001, Category, Severity, Title, Count, Recommendation, Mitre |
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
if ($planRows) { $planRows | Export-Csv "$base`_plan.csv" -NoTypeInformation -Encoding $encOut -Delimiter ';' }

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
/* Identyfikacja PEPIX: pomarańcz #F59F00 i niebieski #4299E1 z logo; wagi i oceny w osobnej, semantycznej palecie */
:root{
  --po:#F59F00;--pb:#4299E1;--pbd:#2B6CB0;--ink:#1A202C;--muted:#5A6472;--line:#E2E8F0;--bg:#F4F5F7;--head:#F1F4F8;
  --c:#B91C1C;--h:#EA580C;--m:#CA8A04;--l:#15803D;--i:#64748B;
  --g-bg:#DCFCE7;--g:#166534;--y-bg:#FEF9C3;--y:#854D0E;--o-bg:#FFEDD5;--o:#9A3412;--r-bg:#FEE2E2;--r:#991B1B;--n-bg:#EDF0F3;--n:#475569
}
*{box-sizing:border-box}
body{font-family:"Segoe UI",Calibri,Arial,sans-serif;font-size:13px;line-height:1.45;color:var(--ink);margin:0;background:var(--bg)}
.wrap{max-width:1200px;margin:0 auto;padding:24px}
header{background:#fff;border-radius:10px;padding:22px 26px 20px;box-shadow:0 1px 3px rgba(0,0,0,.08);position:relative;overflow:hidden}
header::after{content:"";position:absolute;left:0;right:0;bottom:0;height:5px;background:linear-gradient(90deg,var(--po) 0 78%,var(--pb) 78% 100%)}
.hd{display:flex;align-items:center;gap:28px;flex-wrap:wrap}
.logo{height:48px;width:auto}
.ht h1{margin:0 0 4px;font-size:22px;font-weight:700;color:var(--ink)}
.ht p{margin:2px 0;color:var(--muted)}
.ht b{color:var(--ink)}
.conf{margin-top:14px;font-size:12px;font-weight:600;background:#FFF5E0;color:#7A4B00;border:1px solid #F5D08A;padding:6px 10px;border-radius:6px;display:inline-block}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}
.card{background:#fff;border-radius:10px;padding:14px 18px;flex:1;min-width:140px;box-shadow:0 1px 3px rgba(0,0,0,.08);border-top:3px solid var(--line)}
.card .v{font-size:28px;font-weight:700;line-height:1.2}
.card .k{color:var(--muted);font-size:12px}
.card .of{font-size:13px;color:#9AA3AE;font-weight:400;margin-left:2px}
.card.big .v{font-size:38px}
.card.r0{border-top-color:var(--l)}.card.r1{border-top-color:var(--m)}.card.r2{border-top-color:var(--h)}.card.r3{border-top-color:var(--c)}
.card.r0 .v{color:var(--l)}.card.r1 .v{color:var(--m)}.card.r2 .v{color:var(--h)}.card.r3 .v{color:var(--c)}
.card.lvl1{border-top-color:var(--c)}.card.lvl2{border-top-color:var(--h)}.card.lvl3{border-top-color:var(--m)}.card.lvl4,.card.lvl5{border-top-color:var(--l)}
.card.lvl1 .v{color:var(--c)}.card.lvl2 .v{color:var(--h)}.card.lvl3 .v{color:var(--m)}.card.lvl4 .v,.card.lvl5 .v{color:var(--l)}
.card.area{border-top-color:var(--pb)}
.card.area .k{font-weight:600;color:var(--ink);font-size:13px}
.bar{height:8px;background:var(--head);border-radius:4px;margin-top:8px;overflow:hidden}.bar span{display:block;height:100%}
.bar .r0{background:var(--l)}.bar .r1{background:var(--m)}.bar .r2{background:var(--h)}.bar .r3{background:var(--c)}
.matrix{display:flex;gap:12px;flex-wrap:wrap}.mcol{flex:1;min-width:220px}
.mh{font-weight:600;color:var(--ink);padding:6px 8px;border-bottom:2px solid var(--pb);margin-bottom:6px}.mh b{float:right}
.mc{display:flex;justify-content:space-between;gap:8px;padding:6px 9px;margin:4px 0;border-radius:6px;font-size:12px;border-left:4px solid transparent}
.mc.r0{background:var(--g-bg);color:var(--g);border-left-color:var(--l)}.mc.r1{background:var(--y-bg);color:var(--y);border-left-color:var(--m)}
.mc.r2{background:var(--o-bg);color:var(--o);border-left-color:var(--h)}.mc.r3{background:var(--r-bg);color:var(--r);border-left-color:var(--c)}
.st{display:inline-block;padding:2px 9px;border-radius:10px;font-size:11px;font-weight:600;white-space:nowrap}
.st-ok,.st.r0{background:var(--g-bg);color:var(--g)}.st.r1{background:var(--y-bg);color:var(--y)}.st-err,.st.r2{background:var(--o-bg);color:var(--o)}
.st-bad,.st.r3{background:var(--r-bg);color:var(--r)}.st-na{background:var(--n-bg);color:var(--n)}
section{background:#fff;border-radius:10px;padding:20px 22px;margin:16px 0;box-shadow:0 1px 3px rgba(0,0,0,.08)}
h2{color:var(--ink);margin:0 0 12px;font-size:18px;border-left:4px solid var(--po);padding-left:10px}
h3{margin:0 0 6px;font-size:15px}
.tw{overflow-x:auto}
table{border-collapse:collapse;width:100%;margin:8px 0}
th,td{border:1px solid var(--line);padding:6px 9px;text-align:left;vertical-align:top}
th{background:var(--head);color:var(--ink);font-weight:600}
tr:nth-child(even) td{background:#FAFBFC}
.b{display:inline-block;padding:2px 9px;border-radius:10px;font-size:11px;font-weight:700;color:#fff;white-space:nowrap}
.b.critical{background:var(--c)}.b.high{background:var(--h)}.b.medium{background:var(--m)}.b.low{background:var(--l)}.b.info{background:var(--i)}
.f{border-left:5px solid var(--line)}
.f.critical{border-left-color:var(--c)}.f.high{border-left-color:var(--h)}.f.medium{border-left-color:var(--m)}.f.low{border-left-color:var(--l)}.f.info{border-left-color:var(--i)}
.meta{color:var(--muted);font-size:12px;margin-bottom:8px}
.lbl{font-weight:600;color:var(--pbd);margin:12px 0 3px}
pre{background:#1E2430;color:#E6E9EF;padding:10px 12px;border-radius:6px;overflow-x:auto;font-size:12px}
.code{position:relative}.code pre{padding-right:84px}
.cp{position:absolute;top:6px;right:6px;padding:3px 10px;font-size:11px;background:#2D3748;color:#E6E9EF;border:1px solid #4A5568;border-radius:5px}
.cp:hover{background:var(--pbd);border-color:var(--pbd)}.cp.ok{background:var(--l);border-color:var(--l)}
.note{color:var(--muted);font-size:12px}
a{color:var(--pbd)}
button{background:var(--pbd);color:#fff;border:0;padding:6px 12px;border-radius:6px;cursor:pointer}
button:hover{background:var(--pb)}
footer{text-align:center;color:var(--muted);font-size:12px;padding:8px 0 24px}
footer img{height:18px;vertical-align:middle;margin-right:6px}
@media print{
  *{-webkit-print-color-adjust:exact;print-color-adjust:exact}
  body{background:#fff}.wrap{padding:0}
  header,section,.card{box-shadow:none;border:1px solid var(--line)}
  button,.cp{display:none}section{break-inside:avoid-page}
}
</style>
<script>
function toggleAll(o){document.querySelectorAll('details').forEach(d=>d.open=o)}
window.addEventListener('beforeprint',()=>toggleAll(true));
// Przycisk "Kopiuj" przy każdym bloku kodu; zapasowo execCommand, gdy schowek API jest niedostępny (np. starsza przeglądarka lub file://)
function copyText(t){
  if(navigator.clipboard&&window.isSecureContext){return navigator.clipboard.writeText(t)}
  return new Promise(function(ok,err){var a=document.createElement('textarea');a.value=t;a.style.position='fixed';a.style.opacity='0';
    document.body.appendChild(a);a.select();try{document.execCommand('copy')?ok():err()}catch(e){err(e)}document.body.removeChild(a)})
}
document.addEventListener('DOMContentLoaded',function(){
  document.querySelectorAll('pre').forEach(function(p){
    var w=document.createElement('div');w.className='code';p.parentNode.insertBefore(w,p);w.appendChild(p);
    var b=document.createElement('button');b.type='button';b.className='cp';b.textContent='Kopiuj';
    b.addEventListener('click',function(){copyText(p.innerText).then(function(){b.textContent='Skopiowano';b.classList.add('ok');
      setTimeout(function(){b.textContent='Kopiuj';b.classList.remove('ok')},1500)},function(){b.textContent='Błąd kopiowania'})});
    w.appendChild(b);
  });
});
</script>
'@

# Logo PEPIX (PNG z papieru firmowego, osadzone - raport jest jednym plikiem)
$logoB64 = 'iVBORw0KGgoAAAANSUhEUgAAAcsAAAClCAYAAAAzi9bZAAArZElEQVR42u2dB3gU1drHX8u1YbvYUNFLyVIVRCmCVK9e+/0gu6uQ3Q1NuihIz24gUoWQTQKhCygISFVAaTZQFAWpKogFQUCwAWK9CpnvvDuzmyUkm92ZM7NzZt7/8/wfHk0y5d1zzm9Pew8AiUQikUjW0oXMacwvM3/C/B3z38w/Mu9mXsXckbkchYpEIpFIdtPVzNnMvzBLcfg35knM11PoSCQSiWR1ncucxfx7FAj/ZF7BPJDZy3wvczvmfszzFFCGf/d/zDnM51MoSSQSiWRFXcm8Lgp8XzJ3grKHWC9U4Lk76m83Ml9FISWRSCSSlXQp8x4FdKeYeyq9zETlU3qieJ19zOUptCQSiUSygs5hXqkA7jhzE43Xq8f8vXK9N1VCl0QikUgkU2kwFA2fPsjpmi2YC5VrDqcQk0gkEklk3cT8hwK17FJ+B1e4toxyM+Xvzinj2llQtOinKoWaRCKRSKJqqQK0gyAv1ClJm6Dk7SI7mGvEuPY/QJ63xN9dSaEmkUgkkoi6Ogp83hi/dwhK31/5k3Kd0uSO+t1rKeQkEolEEk2dFIj9zHxBHLB0Kf+Nv4tbRU4o/39ijL/F/ZbHld/rQiEnkUgkkmharEBsfhm/VxyWYXVU/v9nZfz9XOX3llDISSQSiSSa3lcg1l8lLB+Aogw/sdRb+b3tFHISiUQiiaa9CsQ6qIAlDq+Gs/18WMbfP6L83g8UchKJRBJXNZkfZ85jXsO8E+TVoeH8qEdBzm7zHvNU5keZb7DAe3+rvJ8zAVheAfK+zOjUdmXBtlHU71KCAhKJRBJMmJrtA4jvVI2S/CpzJYHff5fyHl0TgOUzUe9/GuTk6mUpPFx7jIociUQiiaPrmN/WAMnizhA0DuFh1KEJwLIOyLlj8b8Xx3mf8Krb3VT0SCQSSQzhkOv3HEEZdoGAsZihPPuKBGCJ6gfxD8Gipkb1xEkkEolkct0MRfN0evhZweLhhKLVrOUSgCVA0baTv5nviPG350Z9OelJRZBEIpHMr3U6gjLsWgLF4zLmv5TnfjxBWF4CRatp34/xt49ExeZGKoIkEolkbrUyAJSxkpGbVXOU5z6iALAkYV7XX0Aewo5WPeX/lzYXiblhP1euv5qKIIlEIplfiwyC5VeCxQVPFAlvkckt5XfOU36vJF0b42eZUDRUW52KIIlEIplbeJTUCYNgib5KsPj0iXr2hzhdszkUnWc5googiUQimV93GghKdAsBY/Sy8uyY9LypxmvVh6JFPW8AJSIgkUgkIdTJYFh6BIwRLvbZozw/7qPsAWUf7lxarP9UrvM1c3kqfiQSiSSG+hoMy+6CxglT2UWvGMbTRPCcy0vK+LuLlN/7NOpv3wHxhqNJJBLJ1so0GJb9BY4VDpniHOPvUe/zB/My5gFKr/le5jTlPZeW8Lu43/Q8KnZJ1g2PZF2S4h5Sq5rbf2Ntd9alFBESiVSG+hkMyyctELNrQF4d+0uc7/wryIdAX0fFLUmq4h50c1WXv7/D6X8jxRU4lOL0S8V8yuHyv8t+lsUg2oIiRiKRiqm9wbBMs1DsLgT5lBVMVfcJyAt3cCsIHrf1qfL/8ecXUTFLklJSA/9NcflXR4OxWtsRhbU75Ut1ez8v3dp9ulT78QKpZofgmfB0BY6wf3OqtfY3pCiSSCSQt0MYCcv/UMhJ+kPSPaSWw525JAy/Wh1zpfpDVkjN8z6V7p52oES3mLBbapT1hlT3yTmS49Fhp8N/63AGdqS4MgZVaj24EkWWRLKtrjcYlldTyEm6yuH0dw+DrnbniVKTMe+XCsjS3GrK11KjYW+wnue04sO1axyuQEec86RIk0i20yaDQLmNQk3SF5SujExlGLWwYeaahCFZYo8zfzfrla5kvdO8wqJhWv9f7N85jtSMhyjqJJJtlGYQLHtQqEm6CecYEWTV00adumvsh1xAWdxNs7dKt/dbJFX3jDkVGaZ1Bb5lcB5fJTWzAX0KJJLltUtnUOLxXxdQmDkr6IMWQQ8MzfPCslwv7GQ+xPydQT7K/EXQC+vZ/SflpoEv2xdKiGu4qroy2iK4anjH/q957i5dQFncTUZtlOr2niM53JmFUeDc7kj1D6yc6v9XkorElcxZcdpJNYhUimokUI6a2iw2eHzWrzrC8j4qfrwAmQ43MjiNYqA6yCxFe3IHkKZ2Ms4T0s+8v+LleR542LAeZetAVQapXxBWTcZsMgSUZ85v7pPnN7sVm990+Vc7UjM6VHT3vdjA4lE5gUq5gGoTqRS1SaAcDbZhfPRaGTuMih4vUHpgRDSYlvcDadsokA4VgPTLLJB+m228f5gG0mfjQXrbD9LsblHQ9MHruenQWHdYOjPmIZxwtavRoCx9fjP39Bnzm67AC1WcgQcNKCKVEqiYL1GNIpWi1gmUoyE2jVETODM1mxafBHHT25lLeT5oxAC0HSFU0B6kjcNAOjY9OXAsy3uyQVr0ZBE02bMH9ANlZm0EUs32OaeTDcpS5zfTRhfNb7ozDzuc/mzc2mKCnuVKqlkkDj3LkTaPVUfmD1VC8jfsAzFXpCLHozfphUfzvFCI4Fk1AKSfTArJ4t4+GqRJHRRoekInaXNXVad/CkKoYeZayWywjHbj0PzmC5LDVTS/meIMzHM4MxslsWf5FtUuEoeeZT6FKyT8Avw4yOnd1jDvZD4Ecs5TzHV6kHk783KQ86ZijC+jsPECpQ/ahntom0eIAcloH5kE0vxekR7mIq69Sk/W5aHVr94xp80MyuLzmwh21hOOzG0y4PNsbBLpWW6lGmaYMEdmPeZ/g7ywqgNzb+YM5oEgH0n0X2Vorxok/0iiRHqWs+jjJZWhmszrObpJ8R5lszAodz0rHijD/vk5kBb2VoDphUkce5VdETa3D1giiQLLaN/5zFtSzfTsv+V5zaFbKjsz6hgMS5wnoQNV+QqT8uNqxuHMbzJ/BernsX5mngbyafFmhuW79LGTyhDvJPRXRq48rSv8I+iBPQiYj0aKC8qwj80A6Xll8Q/rLXfm0rN0+d9E0DTL2S4kLMM9TRyeVRIpnExxZtYzEJboOlSPNau80hhsBv22ExxgHq30Os0GS0yIfT4VA1IMreJYF94/48qsBxZEsKwdJD4ow96XF1n0c3x8O215D6u6s1JC6ew6TSgUFZTRbpDxqgLMzP0pqQO1TPYnCsvxVI9VqxXzYjA2X6ik3PNGE8ES7aPiwF2do+KLR1wdB/mUDkxa8A3zPua9IK/IxfnRj5g/UHr6jUz2Ln9wLP9DI1cd74FaCJVpneUhTKvAEr0hM7KtJFcTLFP9AYRLA/9rkhVgib69/2IlsUHmBxpCUwkSX413PbVLCQmHWY3KEVqacdHIAB3fsXWCz7OHigV3XauhfJjpS/CdnMt+0UlQDCaTQwt6hlsLlOiTM0Ga0jEEzEItvUvWA/sUwdJi4meWgSUaTzwJLfpx+dWekl5JReHDb6lNqG0qUw2Ub+6Sibwb9Mmg01rFs+AwdBUqJlyltrx9aaJ38HMs78ciV53wAFwY9MIfkztaD5Rhr8+MrI7tq6pX6fI3QaDc2mOGpUApJzX4FIdiC1Ncgd8ruQdUMAiWYX/MnMmcCvIyeFKRhpsMksXtMQEsw97AjF/2MMtNVSo6mpSh4XMwSx1+g2M5nx+5KgOIOzRXOdi6sDxcEJm7fEdN5B2pGRMQlria1GqwRNcfvDy8D3OywbAsbcXsQWVeBD+vtczLmHHf7BTmbGUO4WmQ95g9xvyA0tvBxUM4h3qVwI1VdeYdJgcl+hTzwyaBZUnG+TZcpLRLgelqkOden2cuYB7LjMlLngJ5G41LGe7GDGC3MN/M/E8bwrKOhpibIbPShcx/cixH7c8agsUsOFaFJTq8MnaSO7TUPjFYOgM/Oh7LOm1FUIZdre3w06x3ecIEsOQ9z/atAl5chDCBuR3zDSZtqFqAvgmzeRsXUbQ0KSx5+hflCxyCF7fnjAF5j6rRMMWcz+s5uWuM+xxWGadNJqhD93D+7K8pgqUHPkSIHJtubViuGqhsI/FCs4SGYJ2B1tjruu2pFyUrw/K2PvPkxT5Of6Ing1QWqHGP9g6ld3qtSUDZUoG7aHHEBVt1Obx/GwHfvZD5bZDTz11qQBm5lOOzPxvjPgUa4nF1kuvRGM5tRJFyffATroK1MijR72dFVsV2SKhX6QosSNbpIkYa308Zil1ooZ5lvH4Z5Gw3yVJDQUEZvWDLyj3LeD1NGb4VHZb3abhu1yTDcrNuMUKAzOlhfVhi3lglo0/cy9+ruAddoZxZecrKoAzb4R5amOLyf2FDWEYnejc6aUJVZX5N9NhlESwjngH67Es1CpYXKCMGaq67OomgLKf0bnnFqOVZsJzX0/qwxPR9SjafuE8kCae3u0PQ9HaJulaHIPYuCyEr61ybwjLsEQZV7uuURShWiBkuqrieYHnGPOfjgsIStVTDwq/LkwRLnmUI1w6cR7CMU1ZIb5eI6/ScGRqKre4OVLc5LCVlUVAlnSv3MovFbCHBssSe1qUCwrKDhmt7kgTLSRzj88pZVydYljIE6ww4QuntOk8stAMoQwkKlJyxVdyZtxIsQ/4a9Dv3706Lxqw5wbLExO/lBIPl1RqGNJcmCZYHOcanO8EyTlg6LJjerixj0gUZloNuJlhGvE8ZLuWtTRaN16sEy1ITJ1wkECxR76m8Ni5Wu9hgUDo4f14VCZbxwtIZ2G3F9HaxfEuXSWFYXkGwPMOvc67YLgvHCuesLiNYluixgsFysIbrP2YwLJ/gGJu9Jd6BYFnCwp7UIXdZNb1dzMQE7UYWYgKGBAtpZRs0cujOnCo1LhrYb/FYdVIRlzY2KEP4RaKhQLCsreH6ywyGJc8jufIJlnHC0uGydnq7ktw0e6uyz9K/iGBZakJlHkNLT9ogVusIlqV6i0CwBGUaQs31/2fgUOwlyv14xeYBgmXcsLR+eruz8sMOWRlOStCDYFmq+3Ko2AfAHj2o8gTLUn23QLDM13CPNINg+V+OccEtUBcSLOOAZdVUfxs7pLcr7tqPF4RgWc05pAbBslRjzswLNFTqejaKlZtgWarfFAiWWnKtrjAIltM5xmVtqXchWJ4pBoyX7JDeLtrNgjvlMy2dATWnstgJluhuGir1KBvFaRTBMqbrCwJLnGNXm80HRxiMSDZ/GIwYPSJYRi3rbJ11ZSi9nc8e6e3CvmPgMnkI1uXvSbAs01s1VOrPbRSnVQTLmJ4lCCxRC5P05TIe1ef8udQkWMYBS4cr0E1Ob7fUVkOwNXzZp0JfEtoMuYpgGZfVpHW7xWYx+pZgGdO46vwcQWDp1XCfjTrDcjTHmByMeSeC5RlDsKvk9HY7bAPKu579ILwKdonKwmpHWPZWEacsG8bpSoIl12xHyYIl5nrVkqC8so6w5DlaM51gGT8s/6zhHVtop15l+BzLlNSAi2Cpa5aaT2wYp/sJllzndZMFS9Q7Gu41WidQ1uH8eaQSLOOAZdXUjFbyKti5thqCdbR95nSKK3BcQ4G1IyxPMidyMovDhjFCDyZYlpkzVhRYDtC4ivwcHWDJ86BnXIxUjmAZByxTXP4MhGWjrDdtA8o7h7+tDMFmTCZYJuy6CcSoq01jNIVgGdN/M58vCCxraLzfwzrAkmfi9LJ3AhAslZ6lyz82tGVk9Pu2gWWdns+FYOlI9TcnWOo6b5lr0xjNIVhynbdMJixR+zTcj/eh0C04fw4ZBMs4YelwZUxFcDTN/sgWoGxZsFfZLhL4XGOhtSssFycQozU2jdEygmWZDggEy6CG++ECoRSOsJzL+XO4nWAZLyxTAwsQHs1zd9kClg0Cq8KwzCJYqj66K17tt2mM1hIsy/TLAsGypcZ7FnACJa7O/ZNjLL6Pb3yIYKmshA08i/BoPGojpbcjWMbrC+OITzkbx+c9gmWZ3iMQLDGbz88a7onJzq/hAMs+nD+DuQTLRGCZGuhsl8Oew+ntmDdwKLh2hmU8i3zusHF8dhEs41qFeZ4gsETNS9J9o/Ul588gjWCZACyruYY0C20d6TPPPuntUlWltyuuSjaGwaNxxMer8zPgNpZtypAnzqPOVBYUPcOcA/JG6wUg7w3FFX9GnnryZQLlqLWNy1F1gWDZVuN9Mc/stRram8E6xP9qgmWiSQlcgRPV2g4/bf30duNC6e1qu7PKEyw1eVgc8RnJ8X4/ML/EjMeoYU7MqzR+bq2YBzG/wvyTDvHZS7CMy/8nECyv4HDvN1Teu4YOsd8c/5p2gmVEVVPlFbF3Dl9v/fR2rozFwEd2huXsOOKzlMN9Dirf6PUWbmOYwzE+2wiWXM9JNQMsUW9xuP/wBO95K/DdV5n4cxAsz4BlKItPnR7PWT69ncPpd3JqYO08Z7kujvh8qPEeL4LxcoC2PXXxb/SmOUt0tmCw7MtxYc11cX6ROqlT7JsQLFWeZ+lwD3031LscYc3epeOxZ06nODWlt0tGzxIXiuBeRUz2/ryyBB1TXY0A+ST3mcrwJM7LrQf5xAuzLGD5VMP110DyhOcQ7tcYn0Q2ohvRs8QhNzw6bBHIR2TlK2UIwTFRGSlYpPwOruQ9blA5elEwWFbl/P44LDuUuTPzA8qwNB7tNVrnOfYTCb213WCZ6wF/rHikuDNbICxrth9/yrLp7VL9k0wOy53MY5kfUeZI1M6t3MXchXm+TpXtxzie4xuV1/6VuQIkV000xmdJkmG5QWmE72a+SGUMKih/jxmbXtepHL0lGCxReyzQo1+SKCwLn+9mfVhuHaXA0hfaoxNTKS7/DCuujA2nt6vmymxmUlguVxomPXSt0nAe5VzhytIJDbEwg7ScNvFCkmD5QgIrTNUMUWOP9BeOz/uZgLAcZwFYPp4oLA8WdLA+LN/JlGGZ54HHyoSlJ+vyFPfQj0MHQQ9cZq30ds7MvZwbDx6wxB7aHQYCYDzHCvevMu6l9rr9TALL3hreYZLBsMQRiRsNigtuN3iFUxn6WUBYNrUALG9MFJbrECJHJlsblq88LcNygje+0yJSWgeqOlyZ3yJgbu+/xDrp7VIzhpkMlt+BvCTcaLXi1MuMBfmLNVzXaRJYPqLhHcYZCEucPy6fhPj4DBqhMBssUccEBuXHCb9t0AMjECLbRlsbllM7sV6lN+5vcDIw2wxpzIB5CCFzS9cphc3zPhE4vd3EECyruwPVTQbLGkkEwf0cKl2sYeNrNFy3mUlg2VDDO2QaBMv9yoKkZGkgh3J0lYCwnCswLMcn/LZ5adAcYflyX+uC8vMcZb7SG1rplpBqtBlyFe5JVNLDSfX6zhcu2XqznB3hpOnrdWgotGwdCZoABi9orHStY1y7iobr3mMSWDYzaE5Iy9aR9kmOEaar26axHFUWEJaPCgxLdfWLQeRzhMlRiw7Fvtpf2TbijSs9WYmq6swYkOLOPBqGZp1es6TGIzYIAUsEvLK3sruJYPlrkobNiutmjZUuPca161pgGDZVwzs0NgCWuB/0XBPESeswcl0BYXkJyLltRQMlnlhyoTpYemAgwuT1IdYD5cGJkV7lVzxqRIoz0AMXyYShWa3dyFP1+i6Q7hq72ZSgbDFhj9KrzDyiUyOhFpYLwTzarKHiPaHTIogBJolNpoZ3KGcALDNMEqcLQNvG+WYCwhL1uoCwfE3122a54QIGk28RKvvzrbmwJ+iBnjxrRhVXxr8ZhKY7XP5fw+Cs2X786fqDXpGa535sGlje3n+x3KtM9Q80GSx7mwiWT2uoeBk6zYkuMUls1KY2O5TgfdTCsrmJypGWIf2HBIXlkwLCUlvbk+OBLgiVBb2sA8otIyPDr+/pVz+kcxxOfzsGpFfC0AwtCOoyWWqYuVZqOenLpIGy8ch3w3OVRyu6gxebDJa3maiRu01DxRsR47oPahwqujzJccHFV4Uqn/91A2D5N6hPNqCH2mv4vF2CwlLEdJcOzW+d64OXEC6rB4oPyr1Fi3pwb2UDI2pKJfeACg5nxlMMUJuiwZmM+c0WEz+Tqrcb9XeoV+kKPKzja6upLNgAn2+iRg6H0E6rrHhjYlz3Po2VelqS47JJw7PnGQDLT8Bc0nJ2aVtBYQnK5yAKKA9yeeNsH5TL88I20ecvcfXrxPRILtjOyag1lZ0ZdVJS/aMczsyvjZ7fbJ73sVSzY+5p5b7P6P2qKgrsYTCfPgP+S9Dv4VC5nwdtR3Gp0ZXMKzU+dxcDYLnKZGXoAg3x8gkMyzECwZJfqs/cNKgS9MAeBM2KfiAdnyEWKLeNiupR+syRBaWaM3APA+cM1sPTfX7zrnFbpBppo/+W75Mx2YjvBSoK7PsmhOViHXpQrThVcNwfjKn6mugcA1yQNIP5jyQMdamB5RQTlqPPVcaro8CwbCIQLB/h+mmP9UBFBpsNCJwZj8tJyM0OyaNTiraIKDlgu5quGmVlnetIzUhLcWUsP2N+s+tkqeFQbfObrabsiyzmUeYps4zqRKsosC+ZsJHLVVn5CmJcs7lOFX6D0uNEgHYAOTECHgaNCSduKGOuE3upOEeL86m9lPfexPn5tqmIvxpYDjFhOVK7IKqLwLA8B+SDyc0OStzmUk6XTz3PC8EwfBY8AdLOMSD9OstckDwwAaR1Q4ogGfTCtvz00DdkU6uSO6sC6232SXEGPigCZ0Cq+8RsqfHId+Kfm8zfLTXIWClVTxt1Wp6fzPy+qjPQxcBXUQPLSSb8SEaorIBTy+ip2fF8xsEGwbKrCcvRCpUx6yEwLFGzBCiXb+j6yQd90IJBaG0YRhPby9l+3hsG0idjQfoyF6Sv84zxPubPxoP00UiQ1g4GCU9LifQkvfAj600OBAFVHec3XRmjWW9wfxicDndW4a3dpzMQvio1GbNJapq9NTRk2yxne+iszfqDV0i3dpsqRfdQq7r8Yyu6+15s8OOrgWXQhB/DIJUVcGaMaza2KSwrq4i/Gli2N2E5Unsc3JOCw3KrAOXSmL3LrMfWjAFpGvPRKEAl3Xk+eIv1gLtlZZlqdaVqheY3nf7nHO7Mw9EgLM0OV2AnA+2g6u5A5SQ9ciXgu4I0WeqlsgLGOoaqkQ1BuUVl/NVkwGlrwnI0TWXcnhYYllUFKZt1DC8NOelQj8GzI4PVcObJDFjTjbAC6xzmp9n978/tEFq1Z1mluIfUSnEGejmc/mxcIMTguIj99zw8OcSRmpnG/r3dBI+ppmeZZcJwq90jNzvGNevbEJapKuOvpmfZxoTlKKgybn3iuLZZYTlSgHL5PZBIAsJylAnfQ+1RS7H2QtaxGSjf0hB/NbB81ITlSO1ZqfFkGDMrLA8KUDZnUVNNEhGW+SZ8jydUVsKJFhie4mUtx7+pgWUnE5ajGSpjF88JLWaE5Z2ClM1HqakmiQjLmSZ8jwyVlTAnxjVvsBEox2mMvxpYPmnCcrRQZfzSBYXlBEHKZwVqqkkiwnKhCd9jrMpKGGux0pU2ASUOw2ndv6YGlhkmLEdrVMZQ1HR33wlSRrskpTTk++CWHA94gx4Yypyf54VJRjjXBwW5Xng21wO98z3wb0zPl7SWtRNclpsO9+T44El8pqBBMQjFwQt5zJnMngkeqCUgLN8xYSM3VWUlDMS45gU2AOU2pQcNSYDlRBOWI7UJHh4REJb3C1ROPzasBLBG+U6EFWusD5pp6wjuATUq/6vbDefl+aALi8PrJovBAfZME4Jp0FAQWH5nwkZuncpK2KuM61oZlIuA36kfamC5zoTlSG0mm6YCwnKOYOW1vr69SC80YY3xq+GGmfUqpaV9QHp3qJwG7/MgSF/lGmNMgLA7G6TNI0BaPQikWV3PyNxzBLeU6BUH9iVhALv+9+H7ze4G0hr2DFvYs+zJlp/NqDhgovidLPbvsM9gyVOhvabR4FzO/ruRyWGJvtxkjdzPKt8jrYzrnrAoKDM5x18NLA+YrAz9S0M8awsGS/yS9ItgZXaGbp88A9C4cCM8vxdI20eDdHKmudLdfZ0P0tpBZ+SE/RB7wRxjgMkYtoavv26w+Q7I/nmmnED+xZ5RcfDAaJPDspGJGrlqGirgA2Vc+1sLAfI3kHPh1tThM1B7+POFJipHbg2xvUEwWD4mYPn9FXjnhh3XASqwBvdNbHSndwZpxxjzJ1L/dpJ8Skqkp8lhaBYzA4Wvh0naj04W4NQV9oVmaqeiIeqCdN2Pd1ILy/4mauS8GipgWV/M9lgAkl+AvLXmMh0/A7WwvNdE5ShbQ4wvFgyWKwQtyz24fdr56XAza2Q/xsb2ladBOjZdrCO6MG9sVO+qj9o4BOVh19B1sNcmUgx+nAbSsr5KOkD5fNLrTQjLD0zUyL2sofJVKuPa7wrWmPzIvJYZRyaccbxfsmE5zSRlCE/e+ErlO/we5z3MAst/Mv8lKCz5LPSZ3QEuYg3rFmxkMVG5qIc/7x0PUn56ZFi2Q8I9Sg90CSeNxzlZUeOwZlDkS8P7i9xwnslgib7eBI1cRebTKp+/kLmsnMRLDW4M8CzK48xHmL9WerbbQV6liacuLFHmbnBfZIbyTbut0kOrlMTPoY0GuJ9jgnL0kIbPbJdgsOwm+EiJ9imgoAfmYeO6aqC4gAgbTycJ9wzHp8Ed8cYgtOpX+TtcSCN6HCJnfHpi5jBNFixzTNDIjdPw/N/Ecf2pOlX4T0HOyXmvModYHsRWGw2x8Jng+ddqeP6VgsFyg+Cw1Jb6jjWmnbBRnddLfECEjatmFfDFva+P/e4H+Dc4nGuVOMztoQzJekJzc2aC5V9J7s3crPTE1D7/u3HcY4QOlX06WE9aYHkI+G1hUaOWGj/PAoFgWVEZUREZln8yX6Hq7XGIjjWmh7BBxXMjrQIJ9MvK3B3rNXcvc/hVTjAgLe9nrRjgdhNle80+HRqKShoL7rIkNnJa5xPnxnGP3jpU9loWhGVrjTFJVjYf3AKldcVzf4FgORCssbK7t7pepRf6h7dFWAkS6G8mRnqXX8QRhwP4u4cLrBeHqPnL3iaDJXpSEhq5Zzk895A47uPUoaL3IliaJqUZjznphwSC5Q6LwPJztbD8DBvSI5OtBwn0yqJ5O1eMGHisMl9bkg8VRBY87TTRMGzxQ5SNWKiB+6yWc3rm++K43206VHTcL9bZYrBswyk2Txj0vDeCnOqPxzNfKwgsa1kElGHfldDb56dDU2xEcbjSipAIrY7NifQuF8aA5cv4O18GrRsHzPYTGo7lmxavMsfCi6s2W+jYwNVUvlHyet4r4oSzXpV9PchHO11OsDzDr4I+iRPCuof5J07PeiiB+yYblqMsBss5ifYqh4u4lzBRT+kYAsWJUucrvfAHJmCwcgy2jIj0sP0mG4YtKednU07PhxvpcWHTas7PmMj871EDKv7rIJ+A4mG+xabDsCWNVvCKBR7x9BTze5yf8RWBYHnAYrDExX3/TASWa608BFt8oU9eeuj0+jNB6YEG+LMV/awdg/BQbNAT91L1ZMEyerjxNeYBIK84rAfygcrXQOmrHzFj0X9B3payScdneyGBGG1MUmNwRBkqXAXycnnsGfQFeasFpulroIwMXGZRWIaNyc1xVKmHMvRWR3nvq8oo17j/FLf+7NLx2Z4WBJaNLQbKsJ9KBJYHC9pbGxLoDZmRFaFnnZid6wMf/mzjMOvHQUnW8KVJh2FFsieBGE0U5J1+U4YXcWgQy8gnzFtAPlJtfZz+jwmGYUXyLYLAcqJF478nEViefr6b9SGxdVTpKfDyvDAIfyZCDlytntkl9IXhD4KlIfOVYbWzUVzaEyzj9vcJxihZsMTsX8cs/Dk0jxeW0rye1ocEHidW2nxdeN7203HWj8Oc7nIc3PzS31WyYSO3PsEY3WSj2KjNptPahuUoXxBYPqhzHHCqJQvkLTR1oSgNZgVl6gVHAycoox163P9FgmUJsAz6zj7Z3o6wXESw1OIOKuJ0iGBJsCzmeoLAcq5O7z9bGZlKRB11WjB3JcGSYKk3LO02DItD2GrOxFtAw7A0DKtqriy5sLwItKWELMmnE5zzL6nN2cf5mfoRLAmWBEu+nq8yTl6CJcEyyoMEgWVbE5WRaFXg3MP8gmBJsCRYmiMvKx7u+zvBkmDJ/DOoSySRDFiu5PzuCzguLsTkEDyTurciWBIsCZZ8PFdjrOYTLAmWEH/i9GTDEjfsn+J4Tzxf9RLgqzEcn+8lgiXBkhb4aPdJZehHix4iWNp+gc8uDeXHaFh25/zuDwF//YN5P6fn+xtiJaogWBIsqWcZl9txiJXV96tRz7LsxriOQLB8l+P9doB+4vlFayDBkmBJPUv1XsyxYgcIlrbtWQ7WWHaMhGVFzu9+H+ir9ZyeE/PfnkOwJFhSzzJxL1KGenjpIjAmsTr1LM1lHocXGAnLwRzvtR30Vy2Oi33uIVgSLAmWiXmsThW7C8HSNrDEBTIeTuXGSFjuMkGZSFQLdR1JIlgSLAmWZxm/ofbQsVKfy/wZwdLysPyt1F6KuWHJ85BnHEU53yBY3qLrQh+CJcGS5izP8EJQv5cyEd3B/BfB0rJzlpjL9HrOZcYoWPLcjpEFxorXvtAhBEuCJcGy9FPTqxtcsbsRLC0FS0wLh+eoXqdTeTEKlgc53QPT2lUwuE7V122hD8GSYGnTYVjcID0D5BMNykPyNJdgKfQwLM7tBUE+meMSncuKEbBsyvEey5NUp97i9Pz3EywJlnbqWWIygf3M25SJe5yLrAbm0tsWgmW6RXuWx5m/Yt6sjEJgztRrDC4nRsByMsd7PJKk+nQ/p+d/mWBJsBQZlm+AnDYO54SGMT+trC5tq3y7v4u5po5DYXoIF0DMomFYQ79ArVZ69bkg7319irkTs1tpbO9UvlRdbbKy0pKTq5Ry/Z84xfhIkuO0m9N7VCBYEixFGobF5fcvMN8M1lZPZSUeDcPqtzoVtwNdCaSSxPOQ55FJfpeunN7DT7AkWIrUs2xnowarNvNG6lnqsvjmDuJhTM3jGO/KSX6Xizn1kvcTLAmWovQsh9m04XKBvCKPepZ8VmU+SCyMqXIc473JJO80mtP7PEiwJFiaHZZ7obQ8jfbQRcqXBZFg6TMhLOcTC22p64Hnql6CJcHSxMOwnam+h4TnCj7O/I6FYannMCwNv9pXvLZm3UiwJFiauWd5NdX1s3QTyEmu3wLqWcbjH6jI2Fp3cypHWQRLgqVZYfkR1fO4hmkx9+izSrxO05zlWX6OigmJiwiWBEuTwjKXamfCwgwy9RVgjWN+DeTVfIVgX1i2p2JBIlgSLK0MS2rk+AqTNGCyBkza8DDImXb6gJzoOp/5eZAzluDw7laQs9X8qOJzU5vBRy9Y1qWPnkSwJFhaGZYNqXbaSnrB8jwKLYkbLOf0sD4kdoyWIZHrgYHFY5DHAIo/Q6BaPQ6zu4XicIpjEdILluWpdhIsNfobCiuJJyyPTetsfUi8n6X0LL3QsXgMgh7ojj/7cLj14zC5YygGPPM26gHLn6lmEiw5+G0KK4kfLH3wIYLi2HRrQ2LVQBmWeWnQ/KyepRfuxZ+tHWztGPwwTelde+Fdk8NyJ9VMgiUHv0BhJXFTngemYAO6J9vaoHheHn6UxnaCy4rHYHw7uBp/Ntfiw9GfjIvAMs/ksFxHNZNgycHjKKwkbgp64VFsQNdZuFd1eFLZPSr2s834O0cnWzcOqwdF4tDa5LCcQzWTYMnBT1NYSdw0uwNclOuDP6d0tC4kNmQqQ7A+6BfjS0MG/s7GYdaMwS+zQCpoH4rDyawsONfksKQeAcGSh9MorCSuYg3oVATF5hHWhMTUTjIss31wbWkxyGkLN+HvTLfoYqcPnlF6lb7Qock8pQcsB1GtJFhy8H0UVhJX5fvgljAoTs60FiTeUXqVQU9o43VMsZ7nFCv2Lk/MKPrCkJMeOv3d7LDsRrWSYMnBjSmsJO5CmFht7vLr/Mgc3cm8dqEMJjEV6l364E/8mwMTrBOHNUVzldk6FB09YNmWaiTBkoNrU1hJ3JWFc5de2IuN6tZR1uhNvdA9MvTYNe4vDV54Irwy1gq97C0jIskYPuE8V6knLB+gGkmw5OCKFFaSLmKNakulByJ9PFbgeUoGucVPKot6vDA10Tiwv5mFf7v0KbFBuXNMpEcp5XuhiU7FRg9YNqPaSLDk4H9SWEl6AtMTbmA/GikeII5OAWnBExFQLlM9LO2DlXiNhb1B+n6qeHHYPKIIlLg9SMciowcsG1BNJFhy8MUUVpKuCnogLdzQrh4I0rEZguR/HSOnc1Oefb7WODDYLsJr4eIYUfLG/jQdpFUDIjEozPOBW+fiogcsb6VaSLDkYBLJgB6mB+5ije3H2OgigDC36onnzAmIvTkgLXmqqCfFnMUtDj4YGb7u0j4gfZ5jzhgcnyGv4i3oEInBdgbKRgYUFT1g6aAaSLDU6P9RSEmGijW4YyLzXj6QVvYHaftokL6dlNzeE0ILkw1EFvHIXl9S7letyk+HVpj9J3wfPOYK7/1FMLk5dQ8XyJ/Fin6hhAtFcfDASAOLiB6wvIlqHsESKBk/SbheZluoFPTCONYQH40CE84JhoYocX+mUVay0EjFnuM1zincShuWdTIQrSl+f3wmI2MQ3jNZLAaH8YsNbn8xuHjoAcsKVOsIlhr9I4WUlFxwpsE9QQ+MyJMXwOxm/o75uEE+xryfeWPQB9PzvdAxmA43Gh0DBBJ7/87sOWYwSL3H/j2gPJtRcfiOfXn5lP27gsXhmVwf3J3EIqEHLK+jmkaw1OjvKKQkEslM0gOW11BYCZYafYRCSiKRzKRKOsDyKgqr7dSacxk6RCElkUhW71mWp7BSz1Kjv6GQkkgkq/csKfMK9Sy1+gCFlEQiUc+SRD3L2D5IISXx1P8DD45uNmoYCCcAAAAASUVORK5CYII='
$sb = [System.Text.StringBuilder]::new()
[void]$sb.Append("<div class=`"wrap`"><header><div class=`"hd`"><img class=`"logo`" alt=`"PEPIX`" src=`"data:image/png;base64,$logoB64`"><div class=`"ht`"><h1>Przegląd bezpieczeństwa Active Directory</h1>")
[void]$sb.Append("<p><b>Klient:</b> $(HtmlEnc $Klient) &nbsp;|&nbsp; <b>Domena:</b> $(HtmlEnc $domain.DNSRoot) &nbsp;|&nbsp; <b>Data:</b> $($now.ToString('dd.MM.yyyy HH:mm'))</p>")
[void]$sb.Append("<p><b>Wykonał:</b> $(HtmlEnc $meta.Uruchomil)$(if ($runAsPriv) { ' (konto uprzywilejowane)' }) ze stacji $(HtmlEnc $env:COMPUTERNAME) &nbsp;|&nbsp; <b>Testy DC:</b> $(HtmlEnc $dcMethod) &nbsp;|&nbsp; PEPIX AD-Check $Version</p></div></div>")
[void]$sb.Append('<div class="conf">DOKUMENT POUFNY - zawiera informacje o podatnościach infrastruktury klienta</div></header>')

function Get-ScoreClass([int]$Points) { if ($Points -ge 30) { 'r3' } elseif ($Points -ge 10) { 'r2' } elseif ($Points -ge 1) { 'r1' } else { 'r0' } }
function Get-MitreLink([string]$Id) {
    if (-not $Id) { return '' }
    $p = $Id -split '\.'
    $u = "https://attack.mitre.org/techniques/$($p[0])/" + $(if ($p.Count -gt 1) { "$($p[1])/" } else { '' })
    "<a href=`"$u`" target=`"_blank`">$(HtmlEnc $Id)</a>"
}

[void]$sb.Append('<div class="cards">')
[void]$sb.Append("<div class=`"card big $(Get-ScoreClass $score)`"><div class=`"v`">$score<span class=`"of`">/100</span></div><div class=`"k`">Wynik ogólny (najgorszy obszar; im mniej, tym lepiej)</div></div>")
[void]$sb.Append("<div class=`"card big lvl$maturity`"><div class=`"v`">$maturity<span class=`"of`">/5</span></div><div class=`"k`">Poziom dojrzałości: $(HtmlEnc $maturityTxt[$maturity])</div></div>")
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
[void]$sb.Append('</div><div class="cards">')
foreach ($a in $areaScore.Keys) {
    $v = $areaScore[$a]
    [void]$sb.Append("<div class=`"card area`"><div class=`"k`">$(HtmlEnc $a)</div><div class=`"v`">$v<span class=`"of`">/100</span></div><div class=`"bar`"><span class=`"$(Get-ScoreClass $v)`" style=`"width:$([Math]::Max($v, 2))%`"></span></div></div>")
}
[void]$sb.Append('</div>')

if ($diff) {
    [void]$sb.Append('<section><h2>Porównanie z poprzednim przeglądem</h2>')
    [void]$sb.Append("<p><b>Nowe znaleziska:</b> $(HtmlEnc (($diff.Nowe) -join ', '))</p><p><b>Usunięte (naprawione):</b> $(HtmlEnc (($diff.Usuniete) -join ', '))</p></section>")
}

[void]$sb.Append('<section><h2>Macierz ryzyka</h2><p class="note">Punkty znalezisk w podziale na obszary i rodzaje ryzyka. Zielone - brak problemów, żółte 1-9 pkt, pomarańczowe 10-29 pkt, czerwone 30+ pkt.</p><div class="matrix">')
foreach ($a in $areaScore.Keys) {
    [void]$sb.Append("<div class=`"mcol`"><div class=`"mh`">$(HtmlEnc $a) <b>$($areaScore[$a])</b></div>")
    foreach ($c in @($matrix | Where-Object Obszar -eq $a)) {
        $t = if ($c.Znaleziska) { "$($c.Punkty) pkt / $($c.Znaleziska) zn." } else { 'OK' }
        [void]$sb.Append("<div class=`"mc $(Get-ScoreClass $c.Punkty)`"><span>$(HtmlEnc $c.Model)</span><span>$t</span></div>")
    }
    [void]$sb.Append('</div>')
}
[void]$sb.Append('</div></section>')

function Add-ComplianceTable($Rows, [string]$Prefix) {
    [void]$sb.Append('<div class="tw"><table><thead><tr><th>Stan</th><th>Środek / zabezpieczenie</th><th>Testy AD</th><th>Znaleziska</th><th>Pkt</th><th>ID znalezisk</th></tr></thead><tbody>')
    foreach ($r in $Rows) {
        $st = if ($r.TestyAD -eq 0) { '<span class="st st-na">poza zakresem</span>' }
              elseif ($r.Znaleziska -eq 0) { '<span class="st st-ok">brak uwag</span>' }
              else { "<span class=`"st $(Get-ScoreClass $r.Punkty)`">wymaga działań</span>" }
        $ids = ($r.Ids | ForEach-Object { "<a href=`"#$(HtmlEnc $_)`">$(HtmlEnc $_)</a>" }) -join ', '
        [void]$sb.Append("<tr><td>$st</td><td><b>$Prefix$(HtmlEnc $r.Kod)</b> $(HtmlEnc $r.Nazwa)</td><td>$($r.TestyAD)</td><td>$($r.Znaleziska)</td><td>$($r.Punkty)</td><td>$ids</td></tr>")
    }
    [void]$sb.Append('</tbody></table></div>')
}
[void]$sb.Append('<section><h2>Odniesienie do NIS2 / UKSC i ISO/IEC 27001</h2>')
[void]$sb.Append('<p class="note">Znaleziska przypisano do środków zarządzania ryzykiem z art. 21 ust. 2 dyrektywy NIS2 (wdrożonych w ustawie o krajowym systemie cyberbezpieczeństwa, Dz. U. 2026 poz. 252) oraz do zabezpieczeń z załącznika A normy ISO/IEC 27001:2022. Zestawienie pokazuje, których wymagań dotyczą techniczne problemy Active Directory; nie jest oceną zgodności podmiotu ani audytem NIS2/UKSC. „Poza zakresem” oznacza środek, którego przegląd AD nie weryfikuje.</p>')
[void]$sb.Append('<div class="lbl">NIS2 art. 21 ust. 2 / UKSC – środki zarządzania ryzykiem</div>')
Add-ComplianceTable $nis2Rows 'lit. '
[void]$sb.Append('<div class="lbl">ISO/IEC 27001:2022 – załącznik A</div>')
Add-ComplianceTable $isoRows 'A.'
[void]$sb.Append('</section>')

[void]$sb.Append('<section><h2>Podsumowanie według kategorii</h2>')
[void]$sb.Append((ConvertTo-HtmlTable $summary))
[void]$sb.Append('</section>')

[void]$sb.Append('<section><h2>Lista znalezisk</h2><div class="tw"><table><thead><tr><th>Waga</th><th>Znalezisko</th><th>Obszar</th><th>Rodzaj ryzyka</th><th>Obiekty</th><th>Pkt</th><th>MITRE ATT&amp;CK</th></tr></thead><tbody>')
foreach ($f in $real) {
    [void]$sb.Append("<tr><td>$(Badge $f.Severity)</td><td><a href=`"#$(HtmlEnc $f.Id)`">$(HtmlEnc $f.Title)</a></td><td>$(HtmlEnc $f.Obszar)</td><td>$(HtmlEnc $f.Model)</td><td>$($f.Count)</td><td>$($weights[$f.Severity])</td><td>$(Get-MitreLink $f.Mitre)</td></tr>")
}
[void]$sb.Append('</tbody></table></div></section>')

[void]$sb.Append('<section><h2>Plan naprawczy</h2>')
$totMin = ($planSum.Values | ForEach-Object { $_[0] } | Measure-Object -Sum).Sum
$totMax = ($planSum.Values | ForEach-Object { $_[1] } | Measure-Object -Sum).Sum
[void]$sb.Append("<p>Szacowana łączna pracochłonność: <b>$(Format-Hours $totMin)-$(Format-Hours $totMax) h</b>.</p>")
[void]$sb.Append('<p class="note">Szacunki są orientacyjne: obejmują przygotowanie, wdrożenie i weryfikację zmian w typowej domenie, bez zakupów, licencji i migracji pojedynczych stacji. Każda zmiana wymaga zgłoszenia i akceptacji przed wykonaniem. Znaleziska krytyczne są zawsze w etapie 1.</p>')
foreach ($k in 1..3) {
    $g = @($planRows | Where-Object Etap -eq $k)
    if (-not $g.Count) { continue }
    [void]$sb.Append("<div class=`"lbl`">$(HtmlEnc $planStages[$k]) &nbsp;<span class=`"note`">($($g.Count) zadań, $(Format-Hours $planSum[$k][0])-$(Format-Hours $planSum[$k][1]) h)</span></div>")
    [void]$sb.Append('<div class="tw"><table><thead><tr><th>Waga</th><th>Zadanie</th><th>Obiekty</th><th>Szacunek</th><th>Uwagi</th></tr></thead><tbody>')
    foreach ($r in $g) {
        [void]$sb.Append("<tr><td>$(Badge $r.Waga)</td><td><a href=`"#$(HtmlEnc $r.Id)`">$(HtmlEnc $r.Znalezisko)</a></td><td>$($r.Obiekty)</td><td>$(Format-Hours $r.GodzinyMin)-$(Format-Hours $r.GodzinyMax) h</td><td>$(HtmlEnc $r.Uwagi)</td></tr>")
    }
    [void]$sb.Append('</tbody></table></div>')
}
[void]$sb.Append('</section>')

[void]$sb.Append('<section><h2>Szczegóły znalezisk</h2><p><button onclick="toggleAll(true)">Rozwiń wszystkie</button> <button onclick="toggleAll(false)">Zwiń wszystkie</button></p></section>')
foreach ($f in $sorted) {
    $sev = $f.Severity.ToLower()
    [void]$sb.Append("<section class=`"f $sev`" id=`"$(HtmlEnc $f.Id)`"><h3>$(Badge $f.Severity) $(HtmlEnc $f.Title)</h3>")
    $mitre = if ($f.Mitre) { " &nbsp;|&nbsp; MITRE ATT&amp;CK: $(Get-MitreLink $f.Mitre)" } else { '' }
    [void]$sb.Append("<div class=`"meta`">$(HtmlEnc $f.Obszar) / $(HtmlEnc $f.Model) &nbsp;|&nbsp; $(HtmlEnc $f.Category) &nbsp;|&nbsp; ID: $(HtmlEnc $f.Id) &nbsp;|&nbsp; Punkty: $($weights[$f.Severity]) &nbsp;|&nbsp; Poziom dojrzałości: $($f.Poziom)$mitre</div>")
    if ($f.NIS2 -or $f.ISO27001) {
        $iso = (($f.ISO27001 -split ',\s*') | Where-Object { $_ } | ForEach-Object { "A.$_" }) -join ', '
        [void]$sb.Append("<div class=`"meta`">NIS2 art. 21 ust. 2 / UKSC: lit. $(HtmlEnc $f.NIS2) &nbsp;|&nbsp; ISO/IEC 27001:2022: $(HtmlEnc $iso)</div>")
    }
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

$stCls = @{ 'Znalezisko' = 'st-bad'; 'Zaliczony' = 'st-ok'; 'Błąd testu' = 'st-err' }
$okRules = @($ruleStatus | Where-Object Status -eq 'Zaliczony').Count
[void]$sb.Append("<section><h2>Sprawdzone reguły</h2><p class=`"note`">Zaliczone: $okRules z $($ruleStatus.Count). Reguły pominięte lub wymagające -UseWinRM nie zostały ocenione.</p><div class=`"tw`"><table><thead><tr><th>Status</th><th>ID</th><th>Obszar</th><th>Rodzaj ryzyka</th><th>Test</th><th>Pkt</th></tr></thead><tbody>")
foreach ($r in @($ruleStatus | Sort-Object Obszar, Model, Id)) {
    $cls = if ($stCls.ContainsKey($r.Status)) { $stCls[$r.Status] } else { 'st-na' }
    $idCell = if ($r.Status -eq 'Znalezisko') { "<a href=`"#$(HtmlEnc $r.Id)`">$(HtmlEnc $r.Id)</a>" } else { HtmlEnc $r.Id }
    [void]$sb.Append("<tr><td><span class=`"st $cls`">$(HtmlEnc $r.Status)</span></td><td>$idCell</td><td>$(HtmlEnc $r.Obszar)</td><td>$(HtmlEnc $r.Model)</td><td>$(HtmlEnc $r.Test)</td><td>$($r.Punkty)</td></tr>")
}
[void]$sb.Append('</tbody></table></div></section>')

[void]$sb.Append('<section><h2>Załącznik A. Inwentaryzacja domeny</h2>')
[void]$sb.Append('<div class="lbl">Domena i polityki</div>'); [void]$sb.Append((ConvertTo-HtmlTable $invDomain))
[void]$sb.Append('<div class="lbl">Kontrolery domeny</div>'); [void]$sb.Append((ConvertTo-HtmlTable $invDCs))
[void]$sb.Append('<div class="lbl">Członkowie grup uprzywilejowanych (rekursywnie)</div>'); [void]$sb.Append((ConvertTo-HtmlTable @($invPriv)))
[void]$sb.Append('<div class="lbl">Relacje zaufania</div>'); [void]$sb.Append((ConvertTo-HtmlTable $invTrusts))
[void]$sb.Append("<div class=`"lbl`">Poziom aktualizacji kontrolerów domeny (wzorzec: Patch Tuesday $(Format-Date $patchRefDate))</div>"); [void]$sb.Append((ConvertTo-HtmlTable @($invPatch | Select-Object -Property * -ExcludeProperty Build, Ubr, Boot, Pending)))
[void]$sb.Append("<div class=`"lbl`">Systemy operacyjne (aktywne konta komputerów; AktywneOstatnio = logowanie w ciągu $StaleDays dni)</div>"); [void]$sb.Append((ConvertTo-HtmlTable @($invOs)))
[void]$sb.Append('</section>')

[void]$sb.Append('<section><h2>Załącznik B. Metodyka i ograniczenia</h2><p>')
[void]$sb.Append('Przegląd wykonano narzędziem PEPIX AD-Check na podstawie odczytu katalogu Active Directory (LDAP), metadanych replikacji, ustawień zasad grupy z SYSVOL oraz nieinwazyjnych testów sieciowych kontrolerów domeny (porty usług, udziały, czas NTP, rekordy DNS). ')
[void]$sb.Append('Punktacja: Critical 25, High 10, Medium 3, Low 1 pkt za znalezisko; wynik obszaru to suma punktów (maks. 100), wynik ogólny to najgorszy obszar. Poziom dojrzałości (1-5) wynika z najpoważniejszego znaleziska. ')
[void]$sb.Append('Konfigurację DC porównano z wybranymi kontrolami CIS Microsoft Windows Server Benchmark (profil L1, kontroler domeny) - nie jest to pełna ocena zgodności z CIS. ')
[void]$sb.Append('Przegląd nie obejmuje testów penetracyjnych, analizy uprawnień (ACL) na obiektach AD i GPO, usług certyfikatów (ADCS) ani stacji końcowych. ')
[void]$sb.Append("Wersje systemów ustalono z atrybutów operatingSystem/operatingSystemVersion kont komputerów (bez łączenia się z komputerami); daty końca wsparcia według Microsoft Lifecycle, stan na $osLifecycleAsOf. ")
[void]$sb.Append("Za nieaktywne uznano konta bez logowania od $StaleDays dni (atrybut lastLogonTimestamp, dokładność do ok. 14 dni). ")
[void]$sb.Append('Wartości odczytane z GPO opisują konfigurację zamierzoną; ustawienia lokalne na DC mogą się od niej różnić. Polecenia naprawcze są przykładowe i wymagają weryfikacji oraz zgłoszenia zmiany przed wykonaniem.')
[void]$sb.Append('</p></section>')
[void]$sb.Append("<footer><img alt=`"PEPIX`" src=`"data:image/png;base64,$logoB64`">PEPIX AD-Check $Version &nbsp;|&nbsp; $($now.ToString('dd.MM.yyyy')) &nbsp;|&nbsp; pepix.pl</footer></div>")

ConvertTo-Html -Head $css -Title "AD $Klient $($now.ToString('yyyy-MM-dd'))" -Body $sb.ToString() | Set-Content "$base.html" -Encoding $encOut
#endregion

Write-Host "`nKlient: $Klient | Domena: $($domain.DNSRoot) | Wynik: $score/100 | Dojrzałość: $maturity/5 | Testy DC: $dcMethod" -ForegroundColor Cyan
Write-Host (($areaScore.Keys | ForEach-Object { "$($_): $($areaScore[$_])" }) -join ' | ') -ForegroundColor Cyan
$real | Format-Table Severity, Category, Title -AutoSize
Write-Host "Raport: $base.html" -ForegroundColor Green
Write-Host "Dane:   $base.json | $base.csv | $base`_obiekty.csv | $base`_plan.csv" -ForegroundColor Green
Write-Host "Plan naprawczy: $($planRows.Count) zadań, $(Format-Hours (($planSum.Values | ForEach-Object { $_[0] } | Measure-Object -Sum).Sum))-$(Format-Hours (($planSum.Values | ForEach-Object { $_[1] } | Measure-Object -Sum).Sum)) h" -ForegroundColor Green
