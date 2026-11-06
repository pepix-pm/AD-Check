# PEPIX AD-Check

Skrypt PowerShell do przeglądu bezpieczeństwa Active Directory. Działa na **zwykłym koncie domenowym**, bez instalacji agentów i bez narzędzi firm trzecich. Wynikiem jest szczegółowy raport HTML gotowy do przekazania klientowi oraz dane JSON/CSV do porównań między przeglądami.

## Wymagania

- Windows PowerShell 5.1 lub nowszy
- Moduł RSAT `ActiveDirectory`
- Stacja w domenie (lub z dostępem do LDAP, SMB/SYSVOL i TCP 445 kontrolerów domeny)
- Zwykłe konto domenowe; konto z uprawnieniami admina na DC tylko w trybie `-UseWinRM`

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

## Uruchomienie z GitHuba (bez kopiowania pliku)

Repozytorium jest prywatne, więc pobranie wymaga tokenu. Użyj **fine-grained PAT** tylko do odczytu:
GitHub → Settings → Developer settings → Fine-grained tokens → *Repository access: Only select repositories* → `AD-Check`, *Permissions: Contents = Read-only*, ważność np. 90 dni. Token trzymaj w Keeperze. Nigdy nie wklejaj go jako tekstu do polecenia – zostałby w historii PowerShella na serwerze klienta.

Wklej w Windows PowerShell 5.1 na serwerze/stacji w domenie klienta:

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$wc = New-Object Net.WebClient
$wc.Headers['Authorization'] = 'token ' + [Net.NetworkCredential]::new('', (Read-Host 'Token GitHub' -AsSecureString)).Password
$wc.Headers['Accept'] = 'application/vnd.github.raw'
$wc.Headers['User-Agent'] = 'PEPIX-ADCheck'
$adcheck = [scriptblock]::Create([Text.Encoding]::UTF8.GetString($wc.DownloadData('https://api.github.com/repos/pepix-pm/AD-Check/contents/PEPIX-ADCheck.ps1')).TrimStart([char]0xFEFF))
$wc.Dispose()
& $adcheck -Klient KLIENT
```

Kolejne uruchomienia w tej samej sesji: `& $adcheck -Klient KLIENT -UseWinRM` itd.

Uwagi:
- Zamiast `iex (irm ...)` używany jest `& ([scriptblock]::Create(...))` – tylko tak da się przekazać parametry (`-Klient`, `-UseWinRM`…). Działa niezależnie od ExecutionPolicy i nie zostawia pliku skryptu na dysku.
- Treść jest dekodowana jawnie jako UTF-8 – PowerShell 5.1 bez tego psuje polskie znaki.
- Konkretną wersję zamiast `main` pobierzesz, dopisując `?ref=v0.3` do adresu.
- Raporty powstają w `%USERPROFILE%\PEPIX-ADCheck\raporty`. Po przekazaniu ich szyfrowanym kanałem usuń je z serwera klienta.

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
| C-OS-EOL | High | Systemy bez wsparcia | T1210 |
| C-LAPS-NONE | High | Brak LAPS w schemacie | T1550.002 |
| C-OS-W10 | Medium | Windows 10 | T1210 |
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

## Ograniczenia

Narzędzie nie zastępuje testów penetracyjnych. Nie analizuje jeszcze uprawnień (ACL) na obiektach AD i GPO, usług certyfikatów (ADCS), uprawnień DCSync ani stacji końcowych. Nieaktywność kont opiera się na `lastLogonTimestamp` (dokładność ok. 14 dni). Polecenia naprawcze w raporcie są przykładowe; przed wykonaniem wymagają weryfikacji i zgłoszenia zmiany.

## Licencja

Do uzupełnienia.

---
PEPIX · Kielce
