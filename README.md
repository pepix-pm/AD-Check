# ADCheck

Skrypt PowerShell do przeglądu bezpieczeństwa Active Directory. Działa na **zwykłym koncie domenowym**, bez instalacji agentów i bez narzędzi firm trzecich. Wynikiem jest szczegółowy raport HTML dla właściciela domeny i administratorów oraz dane JSON/CSV do porównań między przeglądami.

Tworzy i rozwija [PEPIX](https://pepix.pl) – przeglądy bezpieczeństwa Active Directory, wdrożenia poprawek z raportu i stała opieka nad infrastrukturą Microsoft.

## Wymagania

- Windows 10/11 lub Windows Server z PowerShellem (Windows PowerShell 5.1 lub PowerShell 7)
- **Bez RSAT i bez instalowania czegokolwiek** – AD jest odczytywane przez LDAP (`System.DirectoryServices`, wbudowane w Windows)
- Stacja w domenie (lub `-Server`) z dostępem do kontrolerów domeny: LDAP (TCP 389), SMB/SYSVOL (TCP 445), DNS domeny
- Zwykłe konto domenowe; konto z uprawnieniami admina na DC tylko w trybie `-UseWinRM`

Skrypt sprawdza wymagania na starcie i wypisuje wszystkie braki naraz.

## Użycie

```powershell
clear
.\ADCheck.ps1 -Klient KLIENT
.\ADCheck.ps1 -Klient KLIENT -Server firma.local -UseWinRM
.\ADCheck.ps1 -Klient KLIENT -Previous .\raporty\AD_KLIENT_firma.local_20260101-1200.json
```

| Parametr | Opis |
|---|---|
| `-Klient` | Nazwa organizacji w raporcie i w nazwie pliku (wymagany) |
| `-Server` | Domena lub DC do odpytania (domyślnie domena bieżącego użytkownika) |
| `-OutDir` | Katalog wyników (domyślnie `.\raporty` obok skryptu; przy uruchomieniu z GitHuba `%USERPROFILE%\ADCheck\raporty`) |
| `-StaleDays` | Próg nieaktywności kont w dniach (domyślnie 90) |
| `-Previous` | JSON z poprzedniego przeglądu do porównania |
| `-UseWinRM` | Testy DC z rejestru przez WinRM (wymaga admina na DC) |
| `-SkipDCChecks` | Pomija testy kontrolerów domeny |
| `-MaxRows` | Maksymalna liczba obiektów na znalezisko w HTML (domyślnie 500; pełna lista w CSV) |
| `-Silent` | Bez komunikatów postępu w konsoli; skrypt zwraca obiekt z wynikiem i ścieżkami plików (do automatyzacji) |

## Stacja robocza Windows 10/11

Skrypt nie wymaga RSAT ani uprawnień administratora na stacji – wystarczy zwykły PowerShell.

**Stacja w badanej domenie** – zaloguj się kontem domenowym i uruchom bez `-Server`.

**Stacja spoza badanej domeny** (np. komputer audytora podłączony do sieci organizacji lub przez VPN):

1. DNS stacji musi rozwiązywać badaną domenę (serwery DNS = kontrolery tej domeny), bo przez nazwę domeny odczytywany jest m.in. SYSVOL.
2. Uruchom PowerShell z poświadczeniami badanej domeny – bez dołączania stacji do domeny:
   ```powershell
   runas /netonly /user:FIRMA\uzytkownik powershell.exe
   ```
3. W nowym oknie podaj domenę jawnie: `& $adcheck -Klient KLIENT -Server firma.local`.

Raport pokazuje wtedy osobno konto procesu („Uruchomił”) i konto, którym skrypt uwierzytelnił się do LDAP („Konto LDAP”, ustalane zapytaniem LDAP *Who am I*). Ocena, czy przegląd wykonano kontem uprzywilejowanym, dotyczy konta LDAP.

## Uruchomienie z GitHuba (bez kopiowania pliku)

Repozytorium jest publiczne – token nie jest potrzebny. W środowisku produkcyjnym uruchamiaj **wyłącznie wydanie z tagiem i ze sprawdzeniem SHA256**. Wklej w PowerShellu na stacji w badanej domenie:

```powershell
$v='v0.19'; $h='8F95814C31BFCB06AF892E1013A66A31F7CA076E972CC646CBC9B3851CD99A0F'; [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12; $b=(New-Object Net.WebClient).DownloadData("https://raw.githubusercontent.com/pepix-pm/ADCheck/$v/PEPIX-ADCheck.ps1"); if (([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($b)) -replace '-') -ne $h) { throw "SHA256 pobranego pliku nie zgadza się z wydaniem $v - skrypt NIE został uruchomiony" }; & ([scriptblock]::Create([Text.Encoding]::UTF8.GetString($b).TrimStart([char]0xFEFF))) -Klient KLIENT
```

- `$v` i `$h` to tag i SHA256 wydania (lista wydań: zakładka *Releases*). W wydaniu v0.19 plik nazywa się jeszcze `PEPIX-ADCheck.ps1`; od następnego wydania `ADCheck.ps1` – zmień nazwę w adresie razem z `$v` i `$h`. Skrypt uruchamia się tylko wtedy, gdy pobrany plik ma dokładnie ten hash – podmiana pliku lub tagu w repozytorium go zatrzyma.
- **Hash przechowuj poza GitHubem** (np. we własnej dokumentacji lub menedżerze haseł) i stamtąd kopiuj polecenie. Hash pobrany z tego samego repozytorium nie chroni przed przejęciem konta GitHub, bo atakujący zmieniłby oba.
- Pierwsza część włącza TLS 1.2 – bez niej Windows Server 2012 R2/2016 nie połączy się z GitHubem („Nie można utworzyć bezpiecznego kanału SSL/TLS”). Na Windows 10/11 nie przeszkadza.
- Uruchamianie kodu pobranego z sieci bez zapisu na dysk może wywołać alert EDR (zachowanie podobne do technik „fileless”). W organizacjach z EDR, AppLocker lub WDAC pobierz plik z wydania, sprawdź hash (`Get-FileHash .\ADCheck.ps1`) i uruchom go z dysku; przed przeglądem uprzedź zespół monitorujący bezpieczeństwo (SOC).

Gałąź `main` służy wyłącznie do rozwoju i testów w laboratorium. Wersja nieoznaczona tagiem (np. do testu przed wydaniem):

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12; & ([scriptblock]::Create((irm https://raw.githubusercontent.com/pepix-pm/ADCheck/main/ADCheck.ps1).TrimStart([char]0xFEFF))) -Klient KLIENT
```

Sprawdzenie składni bez uruchamiania (np. po zmianach w repo):

```powershell
$e=$null; [void][System.Management.Automation.Language.Parser]::ParseInput((irm https://raw.githubusercontent.com/pepix-pm/ADCheck/main/ADCheck.ps1).TrimStart([char]0xFEFF), [ref]$null, [ref]$e); $e | Format-List Message, @{n='Linia';e={$_.Extent.StartLineNumber}}, @{n='Kod';e={$_.Extent.Text}}
```

Uwagi:
- Dlaczego nie `iex (irm ...)`: `iex` nie przyjmuje parametrów (`-Klient`, `-UseWinRM`…), a do tego wykonuje skrypt w bieżącej sesji – zostawia w niej zmienne skryptu i `$ErrorActionPreference = 'Stop'`. Scriptblock przyjmuje parametry i działa we własnym zakresie. Oba sposoby omijają ExecutionPolicy i nie zapisują skryptu na dysku.
- `.TrimStart([char]0xFEFF)` usuwa znacznik BOM (plik musi go mieć, żeby PowerShell 5.1 z pliku poprawnie czytał polskie znaki). GitHub wysyła `charset=utf-8`, więc `irm` dekoduje polskie znaki poprawnie.
- Wydanie (tag) powstaje dopiero po przetestowaniu wersji w środowisku testowym i w co najmniej jednym środowisku produkcyjnym. Tagi i gałąź `main` są chronione przed nadpisaniem i usunięciem.
- Raporty powstają w `%USERPROFILE%\ADCheck\raporty`. Jeśli przekazujesz je dalej, rób to szyfrowanym kanałem, a potem usuń je ze stacji.
- Zgłaszając błąd lub propozycję zmiany, nie wklejaj fragmentów raportu: nazwy domen, kont, serwerów i wyniki to dane wrażliwe badanej organizacji.

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

- **Plan naprawczy** – znaleziska w trzech etapach (do 30 dni / 30–90 dni / do 12 miesięcy) z szacunkiem pracochłonności i uwagami (zależności, kolejność). Znaleziska krytyczne zawsze w etapie 1. Szacunki są w tabeli `$planMeta` w skrypcie – warto je dostosować do własnych doświadczeń z wdrożeń.
- **Odniesienie do NIS2 / UKSC i ISO/IEC 27001:2022** – każde znalezisko jest przypisane (przez rodzaj ryzyka, `$complianceMap`) do środków z art. 21 ust. 2 NIS2 (wdrożonych w UKSC, Dz. U. 2026 poz. 252) i zabezpieczeń z załącznika A ISO 27001. Raport pokazuje dla każdego środka liczbę testów AD, znaleziska i punkty. To wskazanie, których wymagań dotyczą problemy techniczne – nie ocena zgodności.

Obszar, rodzaj ryzyka i test źródłowy każdej reguły są w katalogu `$ruleCatalog` w skrypcie. Układ raportu jest wzorowany na przeglądach typu PingCastle; teksty, identyfikatory i punktacja są własne.

> **Raporty zawierają informacje o podatnościach badanej organizacji.** Przechowuj je i przekazuj jak dane poufne (szyfrowany kanał, ograniczony dostęp).

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
| D-DCSYNC | Critical / High | Prawo replikacji haseł (DCSync) dla podmiotów spoza DC i administratorów (High, gdy tylko konto synchronizacji Entra ID) | T1003.006 |
| D-ACL-DOMAIN | Critical | GenericAll / WriteDacl / WriteOwner / zapis atrybutów obiektu domeny poza administratorami | T1222.001 |
| D-ACL-ADMINSDHOLDER | Critical | Niestandardowe prawa zapisu lub resetu hasła na AdminSDHolder | T1098 |
| D-ACL-GPO | High | GPO podpięte do domeny lub OU Domain Controllers modyfikowalne przez nie-adminów (obiekt AD i katalog SYSVOL) | T1484.001 |
| P-KRBTGT | High / Critical | Wiek hasła krbtgt (> 180 / > 365 dni) | T1558.001 |
| P-PNE | High | Konta uprzywilejowane z hasłem bez wygasania | T1078.002 |
| P-SPN | High | Konta uprzywilejowane z SPN | T1558.003 |
| P-DA-COUNT | Medium | Więcej niż 5 członków Domain Admins | T1078.002 |
| P-SchemaAdmins, P-AccountOperators, P-ServerOperators, P-PrintOperators, P-BackupOperators | Medium | Niepuste grupy wysokiego ryzyka | T1078.002 |
| P-DnsAdmins | Medium | Niepusta grupa DnsAdmins (wykonanie kodu na DC przez usługę DNS); członkowie traktowani jak konta uprzywilejowane | T1078.002 |
| P-GPCO | Low | Konta spoza administratorów w Group Policy Creator Owners | T1484.001 |
| P-DELEG | Medium | Konta uprzywilejowane bez ochrony przed delegacją | T1558 |
| P-STALE | Medium | Nieużywane aktywne konta uprzywilejowane | T1078.002 |
| P-ADM500 | Medium | Wiek hasła wbudowanego Administratora | T1078.002 |
| P-ADMLOGIN | Medium | Wbudowane konto Administrator używane w ostatnich 35 dniach | T1078.002 |
| P-PROTECTED | Low | Konta uprzywilejowane spoza Protected Users (bez kont z SPN i RID 500) | T1550.002 |
| P-ADMINMAIL | Low | Konta uprzywilejowane z adresem e-mail | T1566 |
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
| C-OWNER | Medium | Komputery, których właścicielem jest zwykłe konto (ryzyko RBCD / odczytu LAPS) | T1134 |
| C-MAQ | Medium | MachineAccountQuota > 0 | T1136.002 |
| C-STALE | Low | Nieużywane konta komputerów | T1078.002 |
| D-RECYCLE | Medium | Kosz AD wyłączony | – |
| D-PWDLEN | Medium | Minimalna długość hasła < 12 | T1110 |
| D-PWDCPLX | Medium | Złożoność haseł wyłączona | T1110 |
| D-LOCKOUT | Medium | Brak blokady konta | T1110.003 |
| D-TRUST-SIDF | Medium | Zaufania zewnętrzne bez filtrowania SID | T1134.005 |
| D-DFL | Low | Poziom funkcjonalny domeny < 2016 | – |
| D-FFL | Low | Poziom funkcjonalny lasu < 2016 | – |
| D-PREWIN2000 | High / Low | Everyone, Anonymous Logon (High) lub Authenticated Users (Low) w Pre-Windows 2000 Compatible Access | T1087.002 |
| D-DSHEURISTICS | High / Medium | dSHeuristics: anonimowe operacje LDAP (7. znak) lub wyłączone poprawki CVE-2021-42291 (28./29. znak) | T1087.002 |
| D-DNS-CREATECHILD | Low | Strefy DNS z CreateChild dla Authenticated Users bez rekordu wildcard (ADIDNS spoofing) | T1557 |
| D-GPO-LLMNR | Medium | Żadne podlinkowane GPO nie wyłącza LLMNR | T1557.001 |
| D-GPO-HARDPATH | Medium / Low | GPO osłabia Hardened UNC Paths dla SYSVOL/NETLOGON lub ich brak przy starszych systemach | T1557 |
| D-GPO-PSLOG | Low | Żadne podlinkowane GPO nie włącza Script Block Logging | T1059.001 |
| D-GPP-PASSWORD | Critical / High | Hasła w preferencjach GPO w SYSVOL: `cpassword` (Critical, odszyfrowywalne przez każdego) lub hasło autologowania jawnym tekstem (High); wszystkie GPO, także niepodlinkowane; raport nie zawiera haseł | T1552.006 |
| DC-OS-EOL | High | DC z systemem bez wsparcia | T1210 |
| DC-SPOOLER | High | Print Spooler na DC | T1187 |
| DC-SMB1 | High | SMBv1 na DC | T1210 |
| DC-ANONLDAP | High | DC zwraca konta na anonimowe zapytanie LDAP (sonda bez uwierzytelnienia) | T1087.002 |
| DC-NETSESSION | Low | Zwykłe konto może wyliczać sesje SMB na DC (NetSessionEnum, brak NetCease) | T1049 |
| DC-LDAPSIGN | Medium | Podpisywanie LDAP niewymagane | T1557 |
| DC-LDAPCBT | Medium | LDAP channel binding niewymuszony | T1557 |
| DC-NTLMV1 | Medium | DC akceptuje NTLMv1/LM | T1557.001 |
| DC-PATCH-OLD | High | DC bez aktualnych poprawek (UBR niższy niż ostatni Patch Tuesday; z WinRM także ostatnia poprawka > 60 dni) | T1210 |
| DC-PATCH-DIFF | Medium | DC z tym samym systemem na różnym poziomie poprawek | T1210 |
| DC-REBOOT | Medium | DC oczekujący na restart lub bez restartu > 60 dni (tylko `-UseWinRM`) | T1210 |
| DC-CIS-REG | wg najgorszego ustawienia | Opcje zabezpieczeń i szablony administracyjne DC niezgodne z CIS L1 (42 ustawienia) | – |
| DC-CIS-AUDIT | wg najgorszego ustawienia | Zaawansowane zasady audytu DC niezgodne z CIS L1 (24 podkategorie) | T1562.002 |
| DC-CIS-RIGHTS | wg najgorszego ustawienia | Przypisanie praw użytkowników na DC niezgodne z CIS L1 (16 praw) | T1078.002 |
| DC-MSBASE | wg najgorszego ustawienia | Ustawienia DC niezgodne z Microsoft Security Baseline (Windows Server 2025, profil DC), których nie zgłosił już CIS ani inny test | – |
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
| DC-REGISTRATION | Medium | Konto DC bez obiektu serwera / NTDS Settings w lesie, niespójne flagi lub zwykły komputer w OU Domain Controllers | T1003.006 |
| DC-SUBNET | Low | Adres DC poza podsieciami AD lub w podsieci innej lokacji | – |

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

Testy działają na zwykłym koncie: metadane replikacji przez LDAP z każdego DC (`msDS-NCReplInboundNeighbors`), udziały i `GPT.INI` przez SMB, czas przez NTP (`w32tm /stripchart`, UDP 123), rekordy SRV przez DNS stacji. Testy sieciowe (porty, udziały, czas, GPO, DNS) pomija `-SkipDCChecks`. Różnica czasu liczona jest względem PDC Emulatora, więc zegar stacji nie wpływa na wynik. Wynik testów sieciowych zależy od zapór między stacją a DC.

## Wersje systemów

Wersja i data końca wsparcia ustalane są z atrybutów `operatingSystem` i `operatingSystemVersion` kont komputerów w AD – bez łączenia się z komputerami. Tabela dat (`$win11Builds`, `$win10Ltsc`, `$serverEol`, `$legacyClient`, `$osLifecycleAsOf`) jest w skrypcie i **wymaga aktualizacji przy nowych wersjach Windows**; nieznane wersje nie są oceniane. Pełny rozkład systemów jest w załączniku A raportu.

## Testy jednostkowe

```powershell
Invoke-Pester .\tests
```

Testy (Pester 5) ładują z pliku skryptu wyłącznie definicje funkcji niezależnych od AD i ich nie uruchamiają.

## Ograniczenia

Narzędzie nie zastępuje testów penetracyjnych. Nie analizuje jeszcze usług certyfikatów (ADCS) ani stacji końcowych. Uprawnienia (ACL) sprawdza na obiekcie domeny (w tym DCSync), AdminSDHolder i GPO podpiętych do domeny i OU Domain Controllers – nie na pojedynczych kontach, grupach, OU i komputerach. Ocena GPO nie uwzględnia flagi Enforced, blokowania dziedziczenia, filtrowania zabezpieczeń ani filtrów WMI. Nieaktywność kont opiera się na `lastLogonTimestamp` (dokładność ok. 14 dni). Polecenia naprawcze w raporcie są przykładowe: przed wykonaniem sprawdź ich skutki w środowisku testowym i wprowadzaj je zgodnie z zasadami zarządzania zmianami w organizacji.

## Zgoda na badanie i ślad w środowisku

Narzędzie wolno uruchamiać **wyłącznie w środowisku, na którego badanie jest pisemna zgoda jego właściciela** (np. umowa lub zlecenie przeglądu z określonym zakresem i terminem). Administrator badający własną domenę również powinien mieć zgodę przełożonych lub osoby odpowiedzialnej za bezpieczeństwo.

„Tylko odczyt” znaczy, że skrypt niczego nie zmienia – nie znaczy, że jest niewidoczny. Wykonuje:

- zapytania LDAP o wszystkie konta, grupy, komputery, GPO, ACL i konfigurację lasu,
- odczyt SYSVOL po SMB (GPO, Registry.pol, GptTmpl.inf),
- sondy kontrolerów domeny: dostępność portów usług AD, potok `\\DC\pipe\spoolss`, wyliczanie sesji SMB (NetSessionEnum), **próbę anonimowego zapytania LDAP**,
- odczyt dziennika zdarzeń DC (bilety Kerberos z DES/RC4), jeśli konto ma do niego dostęp,
- w trybie `-UseWinRM`: zdalne odczyty rejestru i usług na DC.

Te operacje mogą trafić do logów DC i SIEM oraz wywołać alerty (np. Microsoft Defender for Identity: rozpoznanie przez LDAP, wyliczanie sesji SMB) lub zostać zablokowane przez zaporę. Uzgodnij termin przeglądu z właścicielem środowiska i uprzedź zespół monitorujący bezpieczeństwo (SOC).

`-UseWinRM` nie przyjmuje haseł: używa tożsamości Kerberos bieżącej sesji (np. po `runas /netonly`). Poświadczenia nie trafiają do raportu, plików wynikowych ani konsoli; na DC zostaje zwykły ślad logowania sieciowego (zdarzenie 4624, typ 3) i – jeśli włączone – rejestrowanie poleceń PowerShell.

## Licencja

[PolyForm Shield 1.0.0](LICENSE.md) – Required Notice: Copyright PEPIX Piotr Misztal.

W skrócie (wiążący jest tekst licencji):

- możesz bezpłatnie używać ADCheck do dowolnego celu, także komercyjnie, np. do badania domeny własnej firmy lub organizacji, którą administrujesz,
- możesz kopiować i modyfikować skrypt; przekazując go dalej, dołącz tekst licencji (lub jej adres) i linię `Required Notice`,
- **nie możesz** oferować produktu ani usługi konkurencyjnej wobec ADCheck lub wobec usług, które licencjodawca świadczy z jego użyciem – np. sprzedawać przeglądów bezpieczeństwa AD wykonywanych tym narzędziem ani rozpowszechniać go w ramach własnego produktu,
- oprogramowanie jest dostarczane bez gwarancji; autor nie odpowiada za skutki jego użycia.

W sprawie innej licencji (np. do świadczenia usług) skontaktuj się z autorem przez [pepix.pl](https://pepix.pl).

---
[PEPIX](https://pepix.pl) · Kielce
