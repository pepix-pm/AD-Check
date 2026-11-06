# Changelog

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
