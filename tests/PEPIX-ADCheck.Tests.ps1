# Testy jednostkowe funkcji niezależnych od AD (Pester 5). Uruchomienie: Invoke-Pester .\tests
BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot '..\PEPIX-ADCheck.ps1'
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
    $script:parseErrors = $errors
    $names = 'Read-RegistryPol', 'Test-CisValue', 'ConvertFrom-AuditText', 'Get-TopSeverity', 'Show-Val', 'Get-ParentOU', 'Format-Date', 'Format-EncTypes', 'Get-ScoreClass', 'ConvertFrom-LdapResult', 'ConvertTo-LdapFilterValue', 'ConvertFrom-DnToDns', 'ConvertFrom-LdapTime', 'Get-OsLifecycle', 'Test-IpInSubnet', 'Get-DsHeuristicsChar', 'Test-MsSpec', 'Format-MsSpec', 'Format-Count'
    $defs = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
    foreach ($d in $defs) { if ($d.Name -in $names) { . ([scriptblock]::Create($d.Extent.Text)) } }
    # Tabele cyklu życia Windows (zmienne skryptu) potrzebne Get-OsLifecycle
    $vars = 'win11Builds', 'win10Ltsc', 'serverEol', 'serverBuilds', 'sacBuilds', 'legacyClient'
    $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                   $n.Left -is [System.Management.Automation.Language.VariableExpressionAst] }, $false) |
        Where-Object { $_.Left.VariablePath.UserPath -in $vars } | ForEach-Object { . ([scriptblock]::Create($_.Extent.Text)) }

    $ldapMulti = @('serviceprincipalname', 'memberof', 'sidhistory', 'objectclass', 'member', 'serverreferencebl', 'msds-ncreplinboundneighbors', 'msds-replattributemetadata', 'msds-enabledfeaturebl')

    function New-PolBytes([object[]]$Entries) {
        $u = [System.Text.Encoding]::Unicode
        $b = [System.Collections.Generic.List[byte]]::new()
        $b.AddRange([System.Text.Encoding]::ASCII.GetBytes('PReg')); $b.AddRange([BitConverter]::GetBytes([uint32]1))
        foreach ($e in $Entries) {
            $b.AddRange($u.GetBytes('[')); $b.AddRange($u.GetBytes("$($e.Key)`0;")); $b.AddRange($u.GetBytes("$($e.Name)`0;"))
            $b.AddRange([BitConverter]::GetBytes([uint32]4)); $b.AddRange($u.GetBytes(';'))
            $b.AddRange([BitConverter]::GetBytes([uint32]4)); $b.AddRange($u.GetBytes(';'))
            $b.AddRange([BitConverter]::GetBytes([uint32]$e.Data)); $b.AddRange($u.GetBytes(']'))
        }
        , $b.ToArray()
    }
}

Describe 'Skrypt' {
    It 'parsuje się bez błędów' { $script:parseErrors | Should -BeNullOrEmpty }
}

Describe 'Read-RegistryPol' {
    It 'odczytuje wpisy DWORD' {
        $bytes = New-PolBytes @(
            @{ Key = 'Software\Policies\Microsoft\Windows NT\DNSClient'; Name = 'EnableMulticast'; Data = 0 }
            @{ Key = 'Software\Policies\Microsoft\Windows\EventLog\Security'; Name = 'MaxSize'; Data = 196608 }
        )
        $r = @(Read-RegistryPol $bytes)
        $r.Count | Should -Be 2
        $r[0].Key | Should -Be 'Software\Policies\Microsoft\Windows NT\DNSClient'
        $r[0].Name | Should -Be 'EnableMulticast'
        $r[0].Data | Should -Be 0
        $r[1].Data | Should -Be 196608
    }
    It 'oznacza **del. jako usunięcie' {
        $r = @(Read-RegistryPol (New-PolBytes @(@{ Key = 'Software\X'; Name = '**del.Val'; Data = 0 })))
        $r[0].Name | Should -Be 'Val'
        $r[0].Deleted | Should -BeTrue
    }
    It 'zwraca pusty wynik dla złego nagłówka' {
        @(Read-RegistryPol ([byte[]](1, 2, 3, 4, 5, 6, 7, 8))).Count | Should -Be 0
    }
}

Describe 'Test-CisValue' {
    It 'eq: zgodne i niezgodne' {
        Test-CisValue 1 @{ Op = 'eq'; E = 1; D = $null } | Should -BeTrue
        Test-CisValue 0 @{ Op = 'eq'; E = 1; D = $null } | Should -BeFalse
    }
    It 'nieustawione: wartość domyślna albo niezgodne' {
        Test-CisValue $null @{ Op = 'eq'; E = 1; D = 1 } | Should -BeTrue
        Test-CisValue $null @{ Op = 'eq'; E = 1; D = $null } | Should -BeFalse
    }
    It 'le-nz: 0 jest niezgodne' {
        Test-CisValue 900 @{ Op = 'le-nz'; E = 900; D = $null } | Should -BeTrue
        Test-CisValue 0 @{ Op = 'le-nz'; E = 900; D = $null } | Should -BeFalse
    }
    It 'aes: bez RC4 i DES' {
        Test-CisValue 2147483640 @{ Op = 'aes'; E = 0; D = $null } | Should -BeTrue
        Test-CisValue 28 @{ Op = 'aes'; E = 0; D = $null } | Should -BeFalse   # RC4 + AES
    }
}

Describe 'ConvertFrom-AuditText' {
    It 'rozpoznaje ustawienia' {
        ConvertFrom-AuditText 'Success and Failure' | Should -Be 3
        ConvertFrom-AuditText 'Success' | Should -Be 1
        ConvertFrom-AuditText 'Failure' | Should -Be 2
        ConvertFrom-AuditText 'No Auditing' | Should -Be 0
    }
}

Describe 'Format-EncTypes, ConvertFrom-Ldap*, ConvertFrom-DnToDns' {
    It 'opisuje bity szyfrowania' {
        Format-EncTypes 24 | Should -Be '24 (AES128, AES256)'
        Format-EncTypes 7 | Should -Be '7 (DES-CRC, DES-MD5, RC4)'
        Format-EncTypes $null | Should -Match 'nieustawione'
    }
}

Describe 'Get-ScoreClass' {
    It 'progi kolorów' {
        Get-ScoreClass 0 | Should -Be 'r0'
        Get-ScoreClass 9 | Should -Be 'r1'
        Get-ScoreClass 10 | Should -Be 'r2'
        Get-ScoreClass 30 | Should -Be 'r3'
    }
}

Describe 'Warstwa LDAP' {
    It 'ConvertFrom-LdapResult mapuje atrybuty jak moduł AD' {
        $sid = [System.Security.Principal.SecurityIdentifier]'S-1-5-32-544'
        $b = New-Object byte[] $sid.BinaryLength; $sid.GetBinaryForm($b, 0)
        $o = ConvertFrom-LdapResult @{
            'userAccountControl' = @(66050); 'pwdLastSet' = @([int64]0); 'objectSid' = @(, $b)
            'servicePrincipalName' = @('HTTP/a', 'HTTP/b'); 'objectClass' = @('top', 'person', 'user'); 'sAMAccountName' = @('jan')
        }
        $o.Enabled | Should -BeFalse
        $o.PasswordNeverExpires | Should -BeTrue
        $o.PasswordLastSet | Should -BeNullOrEmpty
        $o.SID.Value | Should -Be 'S-1-5-32-544'
        @($o.ServicePrincipalName).Count | Should -Be 2
        $o.ObjectClass | Should -Be 'user'
        $o.SamAccountName | Should -Be 'jan'
    }
    It 'ConvertTo-LdapFilterValue escapuje znaki specjalne' {
        ConvertTo-LdapFilterValue 'CN=Kowalski\, Jan (IT)*' | Should -Be 'CN=Kowalski\5c, Jan \28IT\29\2a'
    }
    It 'ConvertFrom-DnToDns' {
        ConvertFrom-DnToDns 'OU=Biuro,DC=firma,DC=local' | Should -Be 'firma.local'
    }
    It 'ConvertFrom-LdapTime: zerowa data to brak' {
        ConvertFrom-LdapTime '1601-01-01T00:00:00Z' | Should -BeNullOrEmpty
        ConvertFrom-LdapTime '2026-01-02T03:04:05Z' | Should -Not -BeNullOrEmpty
    }
}

Describe 'Funkcje pomocnicze' {
    It 'Get-ParentOU obsługuje przecinek w nazwie' {
        Get-ParentOU 'CN=Kowalski\, Jan,OU=Biuro,DC=firma,DC=local' | Should -Be 'OU=Biuro,DC=firma,DC=local'
    }
    It 'Show-Val dla braku wartości' {
        Show-Val $null @{ 1 = 'x' } | Should -Be 'nieustawione'
    }
    It 'Format-Date dla braku daty' {
        Format-Date $null | Should -Be '—'
    }
    It 'Get-TopSeverity wybiera najwyższą wagę' {
        Get-TopSeverity @([pscustomobject]@{ Waga = 'Low' }, [pscustomobject]@{ Waga = 'High' }) | Should -Be 'High'
    }
}

Describe 'Get-OsLifecycle' {
    It '<Os> <Ver> -> <Typ> <Wersja>' -ForEach @(
        @{ Os = 'Windows Server® 2008 Standard';    Ver = '6.0 (6003)';   Typ = 'Serwer'; Wersja = '2008' }
        @{ Os = 'Windows Server 2008 R2 Enterprise'; Ver = '6.1 (7601)';  Typ = 'Serwer'; Wersja = '2008 R2' }
        @{ Os = 'Windows Server 2016 Standard';     Ver = '10.0 (14393)'; Typ = 'Serwer'; Wersja = '2016' }
        @{ Os = 'Hyper-V Server';                   Ver = '10.0 (17763)'; Typ = 'Serwer'; Wersja = 'Hyper-V 2019' }
        @{ Os = 'Hyper-V Server 2012 R2';           Ver = '6.3 (9600)';   Typ = 'Serwer'; Wersja = 'Hyper-V 2012 R2' }
        @{ Os = 'Windows Small Business Server 2011 Standard'; Ver = '6.1 (7601)'; Typ = 'Serwer'; Wersja = '2008 R2' }
        @{ Os = 'Windows Server Datacenter';        Ver = '10.0 (19042)'; Typ = 'Serwer'; Wersja = 'SAC (build 19042)' }
        @{ Os = 'Windows Server Datacenter';        Ver = '10.0 (20348)'; Typ = 'Serwer'; Wersja = '2022' }
        @{ Os = 'Windows 2000 Server';              Ver = '5.0 (2195)';   Typ = 'Legacy'; Wersja = 'Windows 2000' }
        @{ Os = 'Windows XP Professional x64 Edition'; Ver = '5.2 (3790)'; Typ = 'Legacy'; Wersja = 'Windows XP' }
        @{ Os = 'Windows 10 IoT Enterprise LTSC';   Ver = '10.0 (19044)'; Typ = 'LTSC';   Wersja = 'LTSC 2021' }
        @{ Os = 'Windows 11 Pro';                   Ver = '10.0 (26200)'; Typ = 'W11';    Wersja = '25H2' }
        @{ Os = 'Windows 11 Pro';                   Ver = '10.0 (26300)'; Typ = 'W11';    Wersja = '26H2' }
        @{ Os = 'Windows 11 Pro';                   Ver = '10.0 (28000)'; Typ = 'W11';    Wersja = 'build 28000 (nowsza niż tabela / Insider)' }
        @{ Os = '';                                 Ver = '';             Typ = 'Inne';   Wersja = '' }
        @{ Os = 'Linux';                            Ver = '';             Typ = 'Inne';   Wersja = '' }
    ) {
        $r = Get-OsLifecycle $Os $Ver
        $r.Typ | Should -Be $Typ
        $r.Wersja | Should -Be $Wersja
    }
    It 'Server 2008 bez roku w nazwie nie jest klasyfikowany jako SAC' {
        (Get-OsLifecycle 'Windows Server® 2008 Standard' '6.0 (6002)').Koniec | Should -Be ([datetime]'2020-01-14')
    }
    It 'Hyper-V Server 2016 ma datę końca wsparcia Server 2016' {
        (Get-OsLifecycle 'Hyper-V Server' '10.0 (14393)').Koniec | Should -Be ([datetime]'2027-01-12')
    }
}

Describe 'Test-IpInSubnet' {
    It '<Ip> w <Cidr> = <Wynik>' -ForEach @(
        @{ Ip = '10.1.2.3';     Cidr = '10.1.2.0/24';    Wynik = $true }
        @{ Ip = '10.1.3.3';     Cidr = '10.1.2.0/24';    Wynik = $false }
        @{ Ip = '192.168.5.10'; Cidr = '192.168.0.0/16'; Wynik = $true }
        @{ Ip = '172.16.0.1';   Cidr = '172.16.0.1/32';  Wynik = $true }
        @{ Ip = '8.8.8.8';      Cidr = '0.0.0.0/0';      Wynik = $true }
        @{ Ip = '10.0.0.129';   Cidr = '10.0.0.128/25';  Wynik = $true }
        @{ Ip = '10.0.0.127';   Cidr = '10.0.0.128/25';  Wynik = $false }
        @{ Ip = '10.0.0.1';     Cidr = '10.0.0.0';       Wynik = $false }
        @{ Ip = 'fe80::1';      Cidr = '10.0.0.0/8';     Wynik = $false }
        @{ Ip = '10.0.0.1';     Cidr = 'fe80::/64';      Wynik = $false }
    ) {
        Test-IpInSubnet $Ip $Cidr | Should -Be $Wynik
    }
}

Describe 'Get-DsHeuristicsChar' {
    It 'brak wartości to 0' { Get-DsHeuristicsChar '' 7 | Should -Be '0' }
    It 'krótsza wartość to 0' { Get-DsHeuristicsChar '00000002' 28 | Should -Be '0' }
    It 'siódmy znak' { Get-DsHeuristicsChar '0000002' 7 | Should -Be '2' }
    It 'znak 28 i 29' {
        $v = '0000000001000000000200000000' + '1' + '1'
        Get-DsHeuristicsChar $v 28 | Should -Be '0'
        Get-DsHeuristicsChar $v 29 | Should -Be '1'
        Get-DsHeuristicsChar $v 30 | Should -Be '1'
    }
}

Describe 'Test-MsSpec' {
    It '<Spec> dla <Value> (domyślnie <Default>) = <Wynik>' -ForEach @(
        @{ Value = 1;    Default = $null; Spec = 'eq:1';        Wynik = $true }
        @{ Value = $null; Default = 1;    Spec = 'eq:1';        Wynik = $true }
        @{ Value = $null; Default = $null; Spec = 'eq:1';       Wynik = $false }
        @{ Value = $null; Default = $null; Spec = 'eqn:0';      Wynik = $true }
        @{ Value = 1;    Default = $null; Spec = 'eqn:0';       Wynik = $false }
        @{ Value = 200000; Default = $null; Spec = 'ge:196608'; Wynik = $true }
        @{ Value = 1000; Default = $null; Spec = 'range:1-900'; Wynik = $false }
        @{ Value = 0;    Default = $null; Spec = 'range:1-900'; Wynik = $false }
        @{ Value = 2147483640; Default = $null; Spec = 'in:2147483624,2147483632,2147483640'; Wynik = $true }
        @{ Value = 28;   Default = $null; Spec = 'in:2147483624,2147483632,2147483640'; Wynik = $false }
    ) {
        Test-MsSpec $Value $Default $Spec | Should -Be $Wynik
    }
    It 'Format-MsSpec' {
        Format-MsSpec 'ge:196608' | Should -Be '≥ 196608'
        Format-MsSpec '' | Should -Be '— (brak w baseline)'
    }
}

Describe 'Format-Count' {
    It '<N> -> <Tekst>' -ForEach @(
        @{ N = 1; Tekst = '1 znalezisko' }; @{ N = 2; Tekst = '2 znaleziska' }; @{ N = 5; Tekst = '5 znalezisk' }
        @{ N = 12; Tekst = '12 znalezisk' }; @{ N = 22; Tekst = '22 znaleziska' }; @{ N = 25; Tekst = '25 znalezisk' }
    ) { Format-Count $N | Should -Be $Tekst }
}
