# PEPIX AD-Check

Skrypt PowerShell do przeglądu bezpieczeństwa Active Directory. Działa na **zwykłym koncie domenowym**, bez instalacji agentów i bez narzędzi firm trzecich. Wynikiem jest szczegółowy raport HTML gotowy do przekazania klientowi oraz dane JSON/CSV do porównań między przeglądami.

## Wymagania

- Windows z PowerShellem (Windows PowerShell 5.1 lub PowerShell 7)
- Moduł RSAT `ActiveDirectory`
- Stacja w domenie (lub `-Server`) z dostępem do kontrolerów domeny: AD Web Services (TCP 9389), SMB/SYSVOL (TCP 445)
- Zwykłe konto domenowe; konto z uprawnieniami admina na DC tylko w trybie `-UseWinRM`

Skrypt sprawdza wymagania na starcie i wypisuje wszystkie braki naraz, z podpowiedzią instalacji modułu.

## Użycie

```powershell
clear
.\PEPIX-ADCheck.ps1 -Klient KLIENT
.\PEPIX-ADCheck.ps1 -Klient KLIENT -Server firma.local -UseWinRM
.\PEPIX-ADCheck.ps1 -Klient KLIENT -Previous .\raporty\AD_KLIENT_firma.local_20260101-1200.json
```

| Parametr | Opis |
|---|---|
| `-Klient` | Nazwa klienta w raporcie i nazwie pliku (wymagany) |
| `-Server` | Domena lub DC do odpytania (domyślnie domena bieżącego użytkownika) |
| `-OutDir` | Katalog wyników (domyślnie `.\raporty` obok skryptu; przy uruchomieniu z GitHuba `%USERPROFILE%\PEPIX-ADCheck\raporty`) |
| `-StaleDays` | Próg nieaktywności kont w dniach (domyślnie 90) |
| `-Previous` | JSON z poprzedniego przeglądu do porównania |
| `-UseWinRM` | Testy DC z rejestru przez WinRM (wymaga admina na DC) |
| `-SkipDCChecks` | Pomija testy kontrolerów domeny |
| `-MaxRows` | Maksymalna liczba obiektów na znalezisko w HTML (domyślnie 500; pełna lista w CSV) |

## Stacja robocza Windows 10/11

Docelowo skrypt uruchamiany jest ze stacji roboczej. Jednorazowo, w PowerShellu **jako administrator**:

```powershell
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
```

Moduł pobiera się z Windows Update. Jeśli stacja korzysta z WSUS, instalacja kończy się błędem `0x800f0954` – wtedy włącz w GPO/lokalnych zasadach *Computer Configuration > Administrative Templates > System > Specify settings for optional component installation and component repair* z opcją pobierania bezpośrednio z Windows Update.

Samo uruchomienie skryptu nie wymaga uprawnień administratora stacji.

**Stacja w domenie klienta** – zaloguj się kontem domenowym i uruchom bez `-Server`.

**Stacja spoza domeny klienta** (np. laptop PEPIX w sieci klienta lub przez VPN):

1. DNS stacji musi rozwiązywać domenę klienta (serwery DNS = DC klienta), bo przez nazwę domeny odczytywany jest m.in. SYSVOL.
2. Uruchom PowerShell z poświadczeniami domeny klienta – bez dołączania stacji do domeny:
   ```powershell
   runas /netonly /user:FIRMA\uzytkownik powershell.exe
   ```
3. W nowym oknie podaj domenę jawnie: `& $adcheck -Klient KLIENT -Server firma.local`.

W tym trybie pole „Wykonał” w raporcie pokazuje lokalne konto stacji, nie konto domenowe użyte do odczytu.

## Uruchomienie z GitHuba (bez kopiowania pliku)

Repozytorium jest publiczne – token nie jest potrzebny. Wklej w PowerShellu na stacji w domenie klienta:

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$adcheck = [scriptblock]::Create([Text.Encoding]::UTF8.GetString((New-Object Net.WebClient).DownloadData('https://raw.githubusercontent.com/pepix-pm/AD-Check/main/PEPIX-ADCheck.ps1')).TrimStart([char]0xFEFF))
& $adcheck -Klient KLIENT
```

Kolejne uruchomienia w tej samej sesji: `& $adcheck -Klient KLIENT -UseWinRM` itd.

Uwagi:
- Zamiast `iex (irm ...)` używany jest `& ([scriptblock]::Create(...))` – tylko tak da się przekazać parametry (`-Klient`, `-UseWinRM`…). Działa niezależnie od ExecutionPolicy i nie zostawia pliku skryptu na dysku.
- Treść jest dekodowana jawnie jako UTF-8 – Windows PowerShell bez tego psuje polskie znaki.
- U klienta używaj konkretnej, sprawdzonej wersji: zamień `main` w adresie na tag, np. `v0.5`. `main` może zawierać zmiany jeszcze nieprzetestowane.
- Raporty powstają w `%USERPROFILE%\PEPIX-ADCheck\raporty`. Po przekazaniu ich szyfrowanym kanałem usuń je ze stacji.
- **Repozytorium jest publiczne** – tym bardziej obowiązuje zasada: żadnych nazw klientów, domen, kont ani wyników w repo.

## Wyniki

W katalogu `raporty` powstają pliki `AD_<klient>_<domena>_<data>`:

- `.html` – raport: podsumowanie, karty znalezisk (ryzyko, zalecenie, przykładowa naprawa, obiekty), inwentaryzacja domeny, metodyka
- `.json` – pełne dane do porównań (`-Previous`)
- `.csv` – lista znalezisk
- `_obiekty.csv` – wszystkie obiekty dla wszystkich znalezisk

Punktacja: Critical = 25, High = 10, Medium = 3, Low = 1 za każde znalezisko. Im mniej, tym lepiej.

> **Raporty zawierają informacje o podatnościach klienta.** Nie commituj ich do repozytorium (są w `.gitignore`) i przekazuj tylko szyfrowanym kanałem.

## Jak sprawdzane są kontrolery domeny bez uprawnień admina

| Test | Metoda domyślna | Metoda `-UseWinRM` |
|---|---|---|
| Print Spooler | połączenie z potokiem `\\DC\pipe\spoolss` | stan usługi |
| SMBv1 | sonda negocjacji tylko dialektu SMB1 na TCP 445 | `Get-SmbServerConfiguration` |
| Podpisywanie LDAP | `GptTmpl.inf` z GPO domeny i OU Domain Controllers | rejestr DC |
| LDAP channel binding | jw. | rejestr DC |
| Poziom NTLM (LmCompatibilityLevel) | jw. | rejestr DC |

Odczyt z GPO pokazuje konfigurację zamierzoną; ustawienia lokalne na DC mogą się różnić. Testy, których nie da się rozstrzygnąć, trafiają do sekcji „Testy DC nierozstrzygnięte” i nie są traktowane jako zaliczone.

## Lista testów

| ID | Waga | Test | MITRE ATT&CK |
|---|---|---|---|
| P-KRBTGT | High / Critical | Wiek hasła krbtgt (> 180 / > 365 dni) | T1558.001 |
| P-PNE | High | Konta uprzywilejowane z hasłem bez wygasania | T1078.002 |
| P-SPN | High | Konta uprzywilejowane z SPN | T1558.003 |
| P-DA-COUNT | Medium | Więcej niż 5 członków Domain Admins | T1078.002 |
| P-SchemaAdmins, P-AccountOperators, P-ServerOperators, P-PrintOperators, P-BackupOperators | Medium | Niepuste grupy wysokiego ryzyka | T1078.002 |
| P-DELEG | Medium | Konta uprzywilejowane bez ochrony przed delegacją | T1558 |
| P-STALE | Medium | Nieużywane aktywne konta uprzywilejowane | T1078.002 |
| P-ADM500 | Medium | Wiek hasła wbudowanego Administratora | T1078.002 |
| U-UNCONSTR | Critical | Użytkownicy z delegacją nieograniczoną | T1558 |
| U-ASREP | High | Brak preautentykacji Kerberos | T1558.004 |
| U-PWDNOTREQ | High | Flaga PASSWD_NOTREQD | T1078.002 |
| U-REVERSIBLE | High | Hasło przechowywane odwracalnie | T1003.003 |
| U-DES | High | Wymuszony DES | T1558 |
| U-GUEST | High | Włączone konto Gość | T1078.001 |
| U-SPN | Medium | Konta użytkowników z SPN | T1558.003 |
| U-SIDHIST | Medium | Konta z SIDHistory | T1134.005 |
| U-PNE | Low | Zwykłe konta z hasłem bez wygasania | T1078.002 |
| U-STALE | Low | Nieużywane aktywne konta | T1078.002 |
| U-ADMINCOUNT | Low | Osierocone adminCount=1 | T1098 |
| C-UNCONSTR | Critical | Komputery (nie-DC) z delegacją nieograniczoną | T1558 |
| C-OS-EOL | High | Systemy bez wsparcia (Windows 7/8.1, Server ≤ 2012 R2, wycofane LTSC/SAC) | T1210 |
| C-LAPS-NONE | High | Brak LAPS w schemacie | T1550.002 |
| C-OS-W10 | Medium | Windows 10 (poza LTSC) | T1210 |
| C-OS-FEATURE | Medium | Windows 11 w wersji bez wsparcia (np. 23H2 Pro) | T1210 |
| C-OS-SOON | Medium | Serwery/LTSC z końcem wsparcia w ciągu 12 miesięcy | T1210 |
| C-LAPS-MISSING | Medium | Komputery bez hasła LAPS | T1550.002 |
| C-MAQ | Medium | MachineAccountQuota > 0 | T1136.002 |
| C-STALE | Low | Nieużywane konta komputerów | T1078.002 |
| D-RECYCLE | Medium | Kosz AD wyłączony | – |
| D-PWDLEN | Medium | Minimalna długość hasła < 12 | T1110 |
| D-PWDCPLX | Medium | Złożoność haseł wyłączona | T1110 |
| D-LOCKOUT | Medium | Brak blokady konta | T1110.003 |
| D-TRUST-SIDF | Medium | Zaufania zewnętrzne bez filtrowania SID | T1134.005 |
| D-DFL | Low | Poziom funkcjonalny domeny < 2016 | – |
| DC-OS-EOL | High | DC z systemem bez wsparcia | T1210 |
| DC-SPOOLER | High | Print Spooler na DC | T1187 |
| DC-SMB1 | High | SMBv1 na DC | T1210 |
| DC-LDAPSIGN | Medium | Podpisywanie LDAP niewymagane | T1557 |
| DC-LDAPCBT | Medium | LDAP channel binding niewymuszony | T1557 |
| DC-NTLMV1 | Medium | DC akceptuje NTLMv1/LM | T1557.001 |

## Wersje systemów

Wersja i data końca wsparcia ustalane są z atrybutów `operatingSystem` i `operatingSystemVersion` kont komputerów w AD – bez łączenia się z komputerami. Tabela dat (`$win11Builds`, `$win10Ltsc`, `$serverEol`, `$legacyClient`, `$osLifecycleAsOf`) jest w skrypcie i **wymaga aktualizacji przy nowych wersjach Windows**; nieznane wersje nie są oceniane. Pełny rozkład systemów jest w załączniku A raportu.

## Ograniczenia

Narzędzie nie zastępuje testów penetracyjnych. Nie analizuje jeszcze uprawnień (ACL) na obiektach AD i GPO, usług certyfikatów (ADCS), uprawnień DCSync ani stacji końcowych. Nieaktywność kont opiera się na `lastLogonTimestamp` (dokładność ok. 14 dni). Polecenia naprawcze w raporcie są przykładowe; przed wykonaniem wymagają weryfikacji i zgłoszenia zmiany.

## Licencja

Do uzupełnienia.

---
PEPIX · Kielce
