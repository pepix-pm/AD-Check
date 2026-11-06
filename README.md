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
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/pepix-pm/AD-Check/main/PEPIX-ADCheck.ps1).TrimStart([char]0xFEFF))) -Klient KLIENT
```

Na starszych serwerach (2012 R2/2016) przy błędzie połączenia SSL/TLS najpierw:
`[Net.ServicePointManager]::SecurityProtocol = 'Tls12'`

Uwagi:
- Dlaczego nie `iex (irm ...)`: `iex` nie przyjmuje parametrów (`-Klient`, `-UseWinRM`…), a do tego wykonuje skrypt w bieżącej sesji – zostawia w niej zmienne skryptu i `$ErrorActionPreference = 'Stop'`. Scriptblock przyjmuje parametry i działa we własnym zakresie. Oba sposoby omijają ExecutionPolicy i nie zapisują skryptu na dysku.
- `.TrimStart([char]0xFEFF)` usuwa znacznik BOM (plik musi go mieć, żeby PowerShell 5.1 z pliku poprawnie czytał polskie znaki). GitHub wysyła `charset=utf-8`, więc `irm` dekoduje polskie znaki poprawnie.
- U klienta używaj konkretnej, sprawdzonej wersji: zamień `main` w adresie na tag, np. `v0.5`. `main` może zawierać zmiany jeszcze nieprzetestowane.
- Raporty powstają w `%USERPROFILE%\PEPIX-ADCheck\raporty`. Po przekazaniu ich szyfrowanym kanałem usuń je ze stacji.
- **Repozytorium jest publiczne** – tym bardziej obowiązuje zasada: żadnych nazw klientów, domen, kont ani wyników w repo.

## Wyniki

W katalogu `raporty` powstają pliki `AD_<klient>_<domena>_<data>`:

- `.html` – raport: podsumowanie, karty znalezisk (ryzyko, zalecenie, przykładowa naprawa, obiekty), inwentaryzacja domeny, metodyka
- `.json` – pełne dane do porównań (`-Previous`)
- `.csv` – lista znalezisk
- `_obiekty.csv` – wszystkie obiekty dla wszystkich znalezisk
- `_plan.csv` – plan naprawczy (etap, zadanie, waga, szacunek godzin, uwagi)

### Punktacja i struktura raportu

- Każde znalezisko: Critical = 25, High = 10, Medium = 3, Low = 1 pkt.
- Znaleziska należą do jednego z **czterech obszarów ryzyka**: obiekty nieaktualne, konta uprzywilejowane, zaufania, anomalie. Wynik obszaru = suma punktów, maks. 100. **Wynik ogólny = najgorszy obszar** (0–100, im mniej, tym lepiej).
- **Poziom dojrzałości 1–5** wynika z najpoważniejszego znaleziska (Critical = 1, High = 2, Medium = 3, Low = 4, brak = 5).
- **Macierz ryzyka** pokazuje punkty w podziale obszar × rodzaj ryzyka (np. „Łamanie haseł”, „Pass-the-hash”, „Replikacja i kondycja”).
- **Sprawdzone reguły** – status każdego testu: znalezisko, zaliczony, nie dotyczy, pominięty, wymaga `-UseWinRM`, błąd testu.

- **Plan naprawczy** – znaleziska w trzech etapach (do 30 dni / 30–90 dni / do 12 miesięcy) z szacunkiem pracochłonności i uwagami (zależności, kolejność). Znaleziska krytyczne zawsze w etapie 1. Szacunki są w tabeli `$planMeta` w skrypcie – do dostosowania do realnych czasów PEPIX.
- **Odniesienie do NIS2 / UKSC i ISO/IEC 27001:2022** – każde znalezisko jest przypisane (przez rodzaj ryzyka, `$complianceMap`) do środków z art. 21 ust. 2 NIS2 (wdrożonych w UKSC, Dz. U. 2026 poz. 252) i zabezpieczeń z załącznika A ISO 27001. Raport pokazuje dla każdego środka liczbę testów AD, znaleziska i punkty. To wskazanie, których wymagań dotyczą problemy techniczne – nie ocena zgodności.

Obszar, rodzaj ryzyka i test źródłowy każdej reguły są w katalogu `$ruleCatalog` w skrypcie. Układ raportu jest wzorowany na przeglądach typu PingCastle; teksty, identyfikatory i punktacja są własne PEPIX.

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
| D-KRB-DES | High | DES dopuszczony w konfiguracji kont, komputerów, gMSA, zaufań lub KDC (`msDS-SupportedEncryptionTypes`, USE_DES_KEY_ONLY; KDC tylko z `-UseWinRM`) | T1558 |
| D-KRB-NOAES | High / Medium | Konta bez kluczy AES – hasło sprzed pierwszego DC 2008+ (High, gdy konto uprzywilejowane lub krbtgt) | T1558 |
| D-KRB-TRUST | Medium | Relacje zaufania bez włączonego AES | T1558 |
| DC-KRB-DES-USED | High | Faktycznie wydane bilety DES w ostatnich 7 dniach (zdarzenia 4768/4769, tylko `-UseWinRM`) | T1558 |
| DC-KRB-RC4-USED | Medium | Faktycznie wydane bilety RC4 w ostatnich 7 dniach (tylko `-UseWinRM`) | T1558.003 |
| U-GUEST | High | Włączone konto Gość | T1078.001 |
| U-SPN | Medium | Konta użytkowników z SPN | T1558.003 |
| U-SIDHIST | Medium | Konta z SIDHistory | T1134.005 |
| U-PNE | Low | Zwykłe konta z hasłem bez wygasania | T1078.002 |
| U-STALE | Low | Nieużywane aktywne konta | T1078.002 |
| U-ADMINCOUNT | Low | Osierocone adminCount=1 | T1098 |
| C-UNCONSTR | Critical | Komputery (nie-DC) z delegacją nieograniczoną | T1558 |
| C-OS-EOL | High | Systemy bez wsparcia (Windows 7/8.1, Server ≤ 2012 R2, wycofane LTSC/SAC) | T1210 |
| C-LAPS-READ-BROAD | Critical | Hasła LAPS czytelne dla szerokich grup (Domain Users, Authenticated Users…) | T1555 |
| C-LAPS-NONE | High | Brak LAPS w schemacie | T1550.002 |
| C-LAPS-READABLE | High | Konto użyte do przeglądu (nieuprzywilejowane) widzi hasła LAPS | T1555 |
| C-OS-W10 | Medium | Windows 10 (poza LTSC) | T1210 |
| C-OS-FEATURE | Medium | Windows 11 w wersji bez wsparcia (np. 23H2 Pro) | T1210 |
| C-OS-SOON | Medium | Serwery/LTSC z końcem wsparcia w ciągu 12 miesięcy | T1210 |
| C-LAPS-MISSING | Medium | Komputery bez hasła LAPS | T1550.002 |
| C-LAPS-EXPIRED | Medium | Hasło LAPS przestało się zmieniać (wygasło, a komputer był w sieci) | T1550.002 |
| C-LAPS-LEGACY | Low | Komputery na wycofanym Microsoft LAPS (legacy) | T1550.002 |
| C-LAPS-READERS | Low | Kto spoza DA/EA może czytać hasła LAPS (ACL na OU) – do weryfikacji | T1555 |
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
| DC-PATCH-OLD | High | DC bez aktualnych poprawek (UBR niższy niż ostatni Patch Tuesday; z WinRM także ostatnia poprawka > 60 dni) | T1210 |
| DC-PATCH-DIFF | Medium | DC z tym samym systemem na różnym poziomie poprawek | T1210 |
| DC-REBOOT | Medium | DC oczekujący na restart lub bez restartu > 60 dni (tylko `-UseWinRM`) | T1210 |
| DC-CIS-REG | wg najgorszego ustawienia | Opcje zabezpieczeń i szablony administracyjne DC niezgodne z CIS L1 (42 ustawienia) | – |
| DC-CIS-AUDIT | wg najgorszego ustawienia | Zaawansowane zasady audytu DC niezgodne z CIS L1 (24 podkategorie) | T1562.002 |
| DC-CIS-RIGHTS | wg najgorszego ustawienia | Przypisanie praw użytkowników na DC niezgodne z CIS L1 (16 praw) | T1078.002 |
| DC-CIS-SUMMARY | Info | Procent zgodności i pełna lista sprawdzonych ustawień | – |
| DC-REPL-TSL | Critical | Replikacja nieudana dłużej niż tombstone lifetime | – |
| D-FSMO | Critical | Role FSMO przypisane do nieistniejącego DC | – |
| DC-REPL-FAIL | High | Błędy replikacji AD (z opisem kodu błędu) | – |
| DC-REPL-STALE | High | Replikacja nieudana od ponad 24 h | – |
| D-BACKUP | High | Brak kopii zapasowej AD w ciągu 7 dni (atrybut dSASignature) | T1490 |
| D-SYSVOL-FRS | High | SYSVOL replikowany przez FRS | – |
| DC-SYSVOL-SHARE | High | DC bez udziału SYSVOL/NETLOGON | – |
| DC-TIME | High / Medium | Czas DC różni się od PDC o > 5 min / > 1 min | – |
| D-SINGLEDC | Medium | Tylko jeden kontroler domeny | – |
| DC-MACHINEPWD | Medium | Hasło konta komputera DC starsze niż 45 dni | – |
| DC-PORTS | Medium | Niedostępne porty usług AD na DC (53, 88, 135, 389, 445, 9389, 3268) | – |
| D-GPO-SYNC | Medium | Wersja GPO w AD różna od GPT.INI w SYSVOL na DC | – |
| DC-DNS-SRV | Medium | DC bez rekordu SRV `_ldap._tcp.dc._msdcs` | – |

## Aktualizacje kontrolerów domeny

Poziom poprawek to numer UBR (część wersji po kropce, np. `20348.5761`). Zwykłe konto odczytuje go przez zdalny rejestr – klucz `SOFTWARE\Microsoft\Windows NT\CurrentVersion` jest domyślnie dostępny zdalnie dla użytkowników domeny (wymaga działającej usługi Remote Registry na DC). Z `-UseWinRM` dochodzą: data i numer ostatniej poprawki, ostatni restart, oczekujący restart i źródło aktualizacji (WSUS).

Wzorzec to UBR ostatniej comiesięcznej aktualizacji zabezpieczeń (`$patchRef`, `$patchRefDate` w skrypcie) – **aktualizować co miesiąc po Patch Tuesday**. Gdy wzorzec ma ponad 40 dni, raport o tym ostrzega. Niezależnie od wzorca porównywane są DC z tym samym systemem między sobą.

## Konfiguracja DC wg CIS

Wybrane kontrole CIS Microsoft Windows Server Benchmark (profil L1, kontroler domeny) – nie pełna ocena zgodności z CIS. Treści zaleceń CIS nie są kopiowane (licencja CIS); raport podaje nazwę ustawienia, wartość oczekiwaną i aktualną.

| Obszar | Zwykłe konto (domyślnie) | `-UseWinRM` (admin na DC) |
|---|---|---|
| Opcje zabezpieczeń, szablony administracyjne | GPO domeny i OU Domain Controllers: `GptTmpl.inf`, `Registry.pol` | rzeczywisty rejestr każdego DC |
| Zasady audytu | `audit.csv` w GPO | `auditpol /get /category:*` na każdym DC |
| Przypisanie praw użytkowników | `GptTmpl.inf` w GPO | jw. (odczyt rzeczywisty wymagałby zapisu pliku na DC) |

Ustawienie nieobecne w GPO oceniane jest według wartości domyślnej systemu; jeśli domyślna jest niezgodna z CIS – jako niezgodne. Kolejność GPO jak w pozostałych testach: domena, potem OU Domain Controllers, wg kolejności łączy; flaga Enforced i filtrowanie zabezpieczeń/WMI nie są uwzględniane. Listy kontroli są w skrypcie (`$cisReg`, `$cisAudit`, `$cisRights`).

## LAPS

Skrypt rozpoznaje LAPS legacy (`ms-Mcs-AdmPwd`) i Windows LAPS (`msLAPS-*`). Sprawdza pokrycie, rotację haseł (data wygaśnięcia vs ostatnie logowanie komputera) oraz **kto może odczytać hasła** – z ACL kontenerów, w których są komputery (prawo rozszerzone do atrybutu hasła, wszystkie prawa rozszerzone, pełna kontrola). Sprawdza też, czy konto użyte do przeglądu widzi hasła: filtr LDAP zwraca tylko komputery z czytelnym hasłem – **wartości haseł nie są pobierane ani zapisywane**. Nie są analizowane uprawnienia nadane bezpośrednio na pojedynczych obiektach komputerów ani właściciel obiektu.

## Kondycja domeny i replikacja

Testy działają na zwykłym koncie: metadane replikacji przez AD Web Services, udziały i `GPT.INI` przez SMB, czas przez NTP (`w32tm /stripchart`, UDP 123), rekordy SRV przez DNS stacji. Testy sieciowe (porty, udziały, czas, GPO, DNS) pomija `-SkipDCChecks`. Różnica czasu liczona jest względem PDC Emulatora, więc zegar stacji nie wpływa na wynik. Wynik testów sieciowych zależy od zapór między stacją a DC.

## Wersje systemów

Wersja i data końca wsparcia ustalane są z atrybutów `operatingSystem` i `operatingSystemVersion` kont komputerów w AD – bez łączenia się z komputerami. Tabela dat (`$win11Builds`, `$win10Ltsc`, `$serverEol`, `$legacyClient`, `$osLifecycleAsOf`) jest w skrypcie i **wymaga aktualizacji przy nowych wersjach Windows**; nieznane wersje nie są oceniane. Pełny rozkład systemów jest w załączniku A raportu.

## Testy jednostkowe

```powershell
Invoke-Pester .\tests
```

Testy (Pester 5) ładują z pliku skryptu wyłącznie definicje funkcji niezależnych od AD i ich nie uruchamiają.

## Ograniczenia

Narzędzie nie zastępuje testów penetracyjnych. Nie analizuje jeszcze uprawnień (ACL) na obiektach AD i GPO, usług certyfikatów (ADCS), uprawnień DCSync ani stacji końcowych. Nieaktywność kont opiera się na `lastLogonTimestamp` (dokładność ok. 14 dni). Polecenia naprawcze w raporcie są przykładowe; przed wykonaniem wymagają weryfikacji i zgłoszenia zmiany.

## Licencja

Do uzupełnienia.

---
PEPIX · Kielce
