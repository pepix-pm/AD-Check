# Changelog

## 0.26 – w przygotowaniu

- **P-ACL-TIER0** (Critical/High): niebezpieczne uprawnienia i nietypowi właściciele na kontach i grupach uprzywilejowanych, kontach komputerów DC i OU Domain Controllers. Pomijane są wpisy skopiowane z AdminSDHolder (zgłasza je D-ACL-ADMINSDHOLDER) i podmioty, które już są uprzywilejowane.
- **DC-RBCD** (Critical): RBCD ustawione na koncie kontrolera domeny.
- **D-KCD-DC** (Critical/High): delegacja ograniczona do usług DC, z rozróżnieniem przejścia protokołu.
- Wszystkie testy ACL rozpoznają też zapis msDS-KeyCredentialLink (Shadow Credentials), msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD) i servicePrincipalName (celowany Kerberoasting).
- **P-KeyAdmins**, **P-EnterpriseKeyAdmins** (Medium): niepuste grupy Key Admins / Enterprise Key Admins; ich członkowie są traktowani jak konta uprzywilejowane. Domyślne prawa tych grup do msDS-KeyCredentialLink (Windows Hello for Business) nie są już zgłaszane jako fałszywe alarmy w D-ACL-DOMAIN i P-ACL-TIER0.
- Czytelny komunikat na starcie przy błędnym haśle (0x8007052E) i zablokowanym koncie (0x80070775).

## 0.25 – 2026-11-07

- Poprawka regresji z 0.24: błąd odczytu stref DNS przerywał cały test domeny (Kosz AD, polityka haseł, dSHeuristics, zaufania). Test stref DNS ma teraz własną obsługę błędu (ERR-DNS-ZONES) i oznacza jako „Błąd testu” tylko D-DNS-CREATECHILD.
- Strefy DNS wyszukiwane od korzenia partycji (DomainDnsZones, ForestDnsZones, CN=System), a GPO domeny i DC jednym wyszukiwaniem w CN=Policies. Obiekt, którego konto nie może czytać, nie przerywa już odczytu błędem 0x8007200A, tylko jest pomijany i raportowany.
- INFO-GPO-READ: wyjaśnienie skutku (GPO bez prawa odczytu dla Authenticated Users / Domain Computers może nie być stosowane na komputerach, MS16-072) i polecenia do sprawdzenia uprawnień.

## 0.24 – 2026-11-07

- Testy konfiguracji DC (DC-GPO, CIS, Microsoft Security Baseline) nie przerywają się, gdy konto przeglądu nie może odczytać jednego z GPO podpiętych do domeny lub OU Domain Controllers (np. przez filtrowanie zabezpieczeń). Takie GPO są pomijane i wymienione w nowym znalezisku INFO-GPO-READ z kodem błędu.
- D-DNS-CREATECHILD: błąd odczytu stref DNS daje status „Błąd testu” zamiast fałszywego zaliczenia (pomijany jest tylko brak partycji/kontenera).
- DC-NETSESSION pominięty przy koncie uprzywilejowanym ma status „Pominięty”, także gdy inne testy DC zgłosiły błąd.

## 0.23 – 2026-11-07

- **D-GPP-PASSWORD** (Critical/High): hasła w preferencjach GPO w SYSVOL – `cpassword` (Groups, Services, ScheduledTasks, DataSources, Drives, Printers) i hasło autologowania `DefaultPassword` w Registry.xml; wszystkie GPO, także niepodlinkowane. Raport pokazuje GPO, plik, element i konto, nigdy samo hasło.
- **P-DnsAdmins** (Medium): niepusta grupa DnsAdmins; jej członkowie są traktowani jak konta uprzywilejowane we wszystkich testach (grupa wyszukiwana po nazwie, bo nie ma stałego SID).
- **P-GPCO** (Low): konta spoza administratorów w Group Policy Creator Owners.
- Znaleziska ACL (D-DCSYNC, D-ACL-DOMAIN, D-ACL-ADMINSDHOLDER, D-ACL-GPO): kolumna Czlonkowie – aktywne konta, które efektywnie (rekursywnie) mają prawo nadane grupie.
- Konto LDAP: skrypt pyta serwer, jakim kontem się uwierzytelnił (LDAP Who am I). Przy `runas /netonly` nagłówek raportu pokazuje osobno konto procesu i konto LDAP; ocena „konto uprzywilejowane” dotyczy konta LDAP.
- Zakres oceny pod wynikiem: liczba ocenionych reguł i nieocenionych (wymaga -UseWinRM, pominięte, błąd testu).
- INFO-REFDATA: ostrzeżenie w raporcie i konsoli, gdy wzorzec poprawek DC ma ponad 45 dni lub daty cyklu życia ponad 120 dni.
- Poprawki: P-STALE nie zgłasza kont utworzonych w ostatnich `-StaleDays` dniach; DC-UNKNOWN odróżnia testy pominięte celowo od nierozstrzygniętych; raport HTML5 bez pustej tabeli na końcu; neutralne sformułowania w zaleceniach (bez wewnętrznych procesów i nazw narzędzi).

## 0.22 – 2026-11-07

- Postęp w konsoli: połączenie z domeną, dane bazowe (liczba DC i kont uprzywilejowanych), każdy test z wynikiem (OK / liczba znalezisk i najwyższa waga / błąd) i czasem, zapis raportu, łączny czas przeglądu.
- `-Silent`: bez komunikatów w konsoli; skrypt zwraca obiekt (Klient, Domena, Wynik, Dojrzalosc, Critical, High, Raport, Json, Csv, CzasSek) do użycia w skryptach.
- Jednolita nazwa narzędzia **ADCheck**: plik `ADCheck.ps1` (wcześniej `PEPIX-ADCheck.ps1`), repozytorium `pepix-pm/ADCheck`, nagłówek w konsoli i stopka raportu; domyślny katalog wyników przy uruchomieniu z GitHuba: `%USERPROFILE%\ADCheck\raporty`.
- Licencja **PolyForm Shield 1.0.0** (`LICENSE.md`, nota w pomocy skryptu `.NOTES`).
- Metodyka w raporcie: neutralne sformułowanie o wprowadzaniu poleceń naprawczych (test skutków, zasady zarządzania zmianami organizacji).

## 0.21 – 2026-11-07

- Porównanie konfiguracji DC także z **Microsoft Security Baseline** dla Windows Server 2025 (profil Domain Controller; wartości wg Microsoft Learn, stan 2026-01): kolumny Microsoft i ZgodneMS w tabelach CIS, 7 dodatkowych ustawień spoza wybranych kontroli CIS (m.in. AllowCustomSSPsAPs, UseMachineId, AutoDisconnect).
- **DC-MSBASE** – tylko luki wg Microsoft, których nie zgłosił CIS ani inny test (bez podwójnego liczenia punktów).
- DC-CIS-SUMMARY: w tytule odsetek zgodności wg CIS i wg Microsoft.
- Przy znaleziskach odniesienie do odpowiadającej rekomendacji **Microsoft Defender for Identity** (ocena stanu zabezpieczeń tożsamości) z linkiem do Microsoft Learn; pole MDI w CSV/JSON.

## 0.20 – 2026-11-07

Nowe testy uprawnień (ACL), zwykłe konto, tylko odczyt:
- **D-DCSYNC** – prawo DS-Replication-Get-Changes-All (lub wszystkie prawa rozszerzone) na obiekcie domeny dla podmiotów spoza DC i administratorów; konto synchronizacji Entra ID oznaczane w kolumnie Uwagi.
- **D-ACL-DOMAIN** – GenericAll, WriteDacl, WriteOwner, zapis wszystkich atrybutów lub gPLink na obiekcie domeny (np. Exchange Windows Permissions).
- **D-ACL-ADMINSDHOLDER** – niestandardowe prawa zapisu / resetu hasła na AdminSDHolder.
- **D-ACL-GPO** – GPO podpięte do domeny i OU Domain Controllers modyfikowalne przez nie-adminów (obiekt w AD i katalog w SYSVOL).

## 0.19 – 2026-11-07

Poprawki po pierwszym przebiegu 0.18 w środowisku produkcyjnym:
- **Błąd:** sonda anonimowego LDAP przerywała testy DC wyjątkiem „retrieving member Dispose” (adapter PowerShell dla DirectoryEntry). Skutek: DC-LDAPSIGN, DC-LDAPCBT i DC-NTLMV1 oznaczone jako błąd testu. Metody DirectoryEntry wywoływane teraz przez `.psbase`, sondy są po głównych testach DC i każda ma własną obsługę błędów.
- Windows 11 build 26300 = 26H2 (daty końca wsparcia szacunkowe, do potwierdzenia po GA).
- DC-REGISTRATION: rozróżnia pozostałość po zdegradowanym DC (konto serwera bez flagi DC w OU Domain Controllers, pozostały obiekt serwera w lokacjach) od zwykłego komputera w tej OU.
- DC-SUBNET: osobny tytuł, gdy w AD nie ma żadnej podsieci; opis uwzględnia liczbę lokacji.
- C-OWNER: obiekty, których właściciela nie udało się odczytać, zgłaszane jako Info (C-OWNER-UNKNOWN) zamiast pomijane po cichu.
- Poprawiona odmiana w opisie C-LAPS-MISSING.
- DC-NTLMV1: dla nieustawionego LmCompatibilityLevel podana wartość domyślna (3) i jej skutek. DC-CIS-SUMMARY: w tytule liczba ustawień nieocenionych.
- DC-NETSESSION pomijany (z adnotacją w „Testy DC nierozstrzygnięte”), gdy przegląd uruchomiono kontem uprzywilejowanym – administrator zawsze widzi sesje, więc wynik byłby fałszywie dodatni. Na liście reguł ma status „Pominięty (konto uprzywilejowane)”, a nagłówek raportu informuje o uruchomieniu kontem uprzywilejowanym.

## 0.18 – 2026-11-06

Nowe testy (zwykłe konto, tylko odczyt):
- **DC-ANONLDAP** – sonda: czy DC zwraca konta na anonimowe zapytanie LDAP.
- **DC-NETSESSION** – sonda NetSessionEnum: czy zwykłe konto widzi sesje SMB na DC (brak NetCease).
- **D-DSHEURISTICS** – anonimowe operacje LDAP (7. znak) i wyłączone poprawki CVE-2021-42291 (28./29. znak).
- **D-DNS-CREATECHILD** – strefy DNS w AD z CreateChild dla szerokich grup i bez rekordu wildcard (ADIDNS spoofing).
- **D-GPO-LLMNR**, **D-GPO-HARDPATH**, **D-GPO-PSLOG** – ustawienia z wszystkich podlinkowanych GPO (domena, OU, lokacje; Registry.pol i preferencje rejestru), nie tylko z GPO kontrolerów domeny.
- **P-ADMINMAIL** – konta uprzywilejowane z adresem e-mail.
- Funkcje `Get-LinkedGpoRegistry` i `Get-DsHeuristicsChar`.

## 0.17 – 2026-11-06

Nowe testy (LDAP, zwykłe konto):
- **DC-REGISTRATION** – konto wyglądające na DC bez obiektu serwera lub NTDS Settings w CN=Sites, z niespójną grupą podstawową i flagą DC albo zwykły komputer w OU Domain Controllers.
- **DC-SUBNET** – adres DC poza podsieciami AD lub w podsieci innej lokacji.
- **D-FFL** – poziom funkcjonalny lasu < 2016.
- **P-ADMLOGIN** – wbudowany Administrator używany w ostatnich 35 dniach.
- **P-PROTECTED** – konta uprzywilejowane spoza Protected Users (bez kont z SPN i RID 500); brak grupy Protected Users.
- **C-OWNER** – komputery, których właścicielem obiektu jest konto spoza administratorów (ryzyko RBCD, odczytu LAPS).
- **D-PREWIN2000** – Everyone / Anonymous Logon / Authenticated Users w Pre-Windows 2000 Compatible Access.
- Funkcja `Test-IpInSubnet` z testami Pester.

## 0.16 – 2026-11-06

- Klasyfikacja systemów serwerowych także po numerze build, gdy nazwa nie zawiera roku: „Windows Server® 2008”, „Hyper-V Server” (2016/2019), Small Business Server 2011. Wcześniej takie systemy z buildem < 20348 trafiały błędnie do „SAC”; jako SAC oznaczane są teraz tylko buildy 16299–19042.
- Hyper-V Server rozpoznawany jako serwer (wcześniej pomijany, bo nazwa nie zawiera „Windows”).
- Windows 11 z buildem nowszym niż tabela (np. 26300, Insider) opisany jako „nowsza niż tabela / Insider” – bez oceny.
- C-LAPS-MISSING ocenia tylko komputery z Windows; konta bez systemu Windows (Linux, NAS, klastry, brak `operatingSystem`) są pomijane i liczone w opisie.
- Testy Pester dla `Get-OsLifecycle`; poprawka nazwy bloku `Describe` dla Pester 6.

## 0.15 – 2026-11-06

- **Bez RSAT:** odczyt AD przez LDAP (`System.DirectoryServices`) zamiast modułu ActiveDirectory. Skrypt działa na każdym Windows bez instalacji i bez uprawnień administratora na stacji. Replikacja i kopia AD z atrybutów konstruowanych `msDS-NCReplInboundNeighbors` / `msDS-ReplAttributeMetaData`; członkostwo rekursywne przez LDAP_MATCHING_RULE_IN_CHAIN.
- Wymagania: zamiast modułu AD sprawdzane połączenie LDAP z domeną (TCP 389).

## 0.14 – 2026-11-06

- Przycisk „Kopiuj” przy blokach z poleceniami naprawczymi w raporcie HTML (ukryty na wydruku).

## 0.13 – 2026-11-06

- Wygląd raportu w identyfikacji PEPIX: logo z papieru firmowego (osadzone w HTML), kolory marki (#F59F00, #4299E1), spójna paleta wag i ocen, stopka, poprawiony wydruk (kolory zachowane).

## 0.12 – 2026-11-06

- Plan naprawczy: trzy etapy (do 30 dni / 30–90 dni / do 12 miesięcy), szacunek pracochłonności w godzinach, uwagi i zależności; sekcja w HTML, `Plan` w JSON, plik `_plan.csv`.

## 0.11 – 2026-11-06

- Odniesienie do NIS2 art. 21 ust. 2 / UKSC i ISO/IEC 27001:2022 (załącznik A): pola NIS2 i ISO27001 w znaleziskach (HTML, JSON, CSV) i sekcja zestawienia w raporcie.

## 0.10 – 2026-11-06

- Raport w układzie zbliżonym do PingCastle: wynik 0–100 w czterech obszarach ryzyka (obiekty nieaktualne, konta uprzywilejowane, zaufania, anomalie), wynik ogólny = najgorszy obszar, poziom dojrzałości 1–5, macierz ryzyka, lista sprawdzonych reguł ze statusem, linki MITRE ATT&CK.
- Katalog reguł `$ruleCatalog`; znaleziska mają pola Obszar, Model, Poziom (JSON, CSV).
- **Zmiana znaczenia `Meta.Wynik`:** wcześniej suma punktów bez limitu, teraz 0–100 (najgorszy obszar). Porównanie `-Previous` z raportem sprzed 0.10 pokazuje różnicę w innych jednostkach.

## 0.9 – 2026-11-06

- Kerberos i szyfrowanie: DES w konfiguracji kont/komputerów/zaufań/KDC (D-KRB-DES), konta bez kluczy AES (D-KRB-NOAES), zaufania bez AES (D-KRB-TRUST); z `-UseWinRM` faktyczne bilety DES/RC4 z dziennika Security DC (DC-KRB-DES-USED, DC-KRB-RC4-USED).
- P-SPN i U-SPN: kolumna Szyfrowanie (RC4 / AES).

## 0.8 – 2026-11-06

- Aktualizacje DC: poziom poprawek (UBR) przez zdalny rejestr na zwykłym koncie, porównanie z ostatnim Patch Tuesday (DC-PATCH-OLD) i między DC (DC-PATCH-DIFF); z `-UseWinRM` ostatnia poprawka, restart, oczekujący restart, WSUS (DC-REBOOT). Tabela w załączniku A.

## 0.7 – 2026-11-06

- Konfiguracja DC wg CIS L1: opcje zabezpieczeń i szablony administracyjne (DC-CIS-REG), zasady audytu (DC-CIS-AUDIT), przypisanie praw (DC-CIS-RIGHTS), podsumowanie zgodności (DC-CIS-SUMMARY). Zwykłe konto: GPO z SYSVOL; `-UseWinRM`: rejestr i auditpol każdego DC.
- Parser `Registry.pol` (`Read-RegistryPol`) i zbiorczy odczyt GPO DC (`Get-DcGpoPolicy`).
- Testy jednostkowe Pester 5 w `tests/`.

## 0.6 – 2026-11-06

- Nowa kategoria „Kondycja domeny i replikacja”: błędy i opóźnienia replikacji (z tombstone lifetime), kopia zapasowa AD (dSASignature), SYSVOL na FRS, osierocone role FSMO, jeden DC, hasło konta komputera DC, porty usług AD, udziały SYSVOL/NETLOGON, czas DC względem PDC, spójność GPO AD–SYSVOL, rekordy SRV w DNS.
- LAPS: rozpoznanie legacy / Windows LAPS, pokrycie w opisie; nowe testy C-LAPS-EXPIRED (hasło przestało się zmieniać), C-LAPS-LEGACY, C-LAPS-READ-BROAD i C-LAPS-READERS (kto może czytać hasła – ACL na OU), C-LAPS-READABLE (konto przeglądu widzi hasła; bez pobierania wartości).
- Poprawka: test COMPUTERS kończył się błędem, gdy w schemacie nie ma atrybutów LAPS (null w `-Properties`) – w takiej domenie nie raportowano żadnego znaleziska o komputerach ani braku LAPS.

## 0.5 – 2026-11-06

- Systemy operacyjne oceniane według dat Microsoft Lifecycle (wersja z `operatingSystemVersion`) zamiast samej nazwy: rozpoznawane wersje Windows 11, LTSB/LTSC, Server SAC; kolumny Wersja i KoniecWsparcia.
- Nowe testy: C-OS-FEATURE (Windows 11 w wersji bez wsparcia), C-OS-SOON (serwery/LTSC z końcem wsparcia w ciągu 12 miesięcy).
- C-OS-W10 nie obejmuje już Windows 10 LTSC (oceniane osobno według dat). DC-OS-EOL według dat zamiast nazwy.
- Załącznik A: rozkład systemów operacyjnych (liczba komputerów, aktywne, koniec wsparcia).

## 0.4 – 2026-11-06

- Sprawdzanie wymagań na starcie zamiast wymuszania wersji PowerShella: Windows, moduł ActiveDirectory (z podpowiedzią instalacji dla serwera/stacji), ustalona domena, plik `-Previous`, połączenie z AD (ADWS TCP 9389). Wszystkie braki zgłaszane naraz.
- Pliki wynikowe zawsze w UTF-8 z BOM, także w PowerShell 7 (wcześniej polskie znaki w CSV/HTML mogły się psuć).

## 0.3 – 2026-11-06

- Uruchamianie bez kopiowania pliku: skrypt działa jako scriptblock pobrany z prywatnego repo GitHub (instrukcja w README).
- Usunięto `#Requires` (nieobsługiwane w scriptblocku); wersja PowerShell i moduł ActiveDirectory sprawdzane ręcznie z czytelnym komunikatem.
- Domyślny `-OutDir` bez `$PSScriptRoot`: przy uruchomieniu z GitHuba `%USERPROFILE%\PEPIX-ADCheck\raporty`.
- Poprawka: ustawienia DC z GPO nie trafiały do testów przy uruchomieniu jako scriptblock (`$script:gpoSettings`).
- Poprawka: funkcja `H` przesłaniana przez wbudowany alias `h` (`Get-History`) – zmieniona na `HtmlEnc`; generowanie HTML kończyło się błędem.

## 0.2

- Wersja wyjściowa.
