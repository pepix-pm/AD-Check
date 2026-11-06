# Changelog

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
