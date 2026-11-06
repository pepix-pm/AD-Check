# Testy jednostkowe funkcji niezależnych od AD (Pester 5). Uruchomienie: Invoke-Pester .\tests
BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot '..\PEPIX-ADCheck.ps1'
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
    $script:parseErrors = $errors
    $names = 'Read-RegistryPol', 'Test-CisValue', 'ConvertFrom-AuditText', 'Get-TopSeverity', 'Show-Val', 'Get-ParentOU', 'Format-Date'
    $defs = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
    foreach ($d in $defs) { if ($d.Name -in $names) { . ([scriptblock]::Create($d.Extent.Text)) } }

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
