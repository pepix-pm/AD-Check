# Changelog

## 0.3 – 2026-11-06

- Uruchamianie bez kopiowania pliku: skrypt działa jako scriptblock pobrany z prywatnego repo GitHub (instrukcja w README).
- Usunięto `#Requires` (nieobsługiwane w scriptblocku); wersja PowerShell i moduł ActiveDirectory sprawdzane ręcznie z czytelnym komunikatem.
- Domyślny `-OutDir` bez `$PSScriptRoot`: przy uruchomieniu z GitHuba `%USERPROFILE%\PEPIX-ADCheck\raporty`.
- Poprawka: ustawienia DC z GPO nie trafiały do testów przy uruchomieniu jako scriptblock (`$script:gpoSettings`).
- Poprawka: funkcja `H` przesłaniana przez wbudowany alias `h` (`Get-History`) – zmieniona na `HtmlEnc`; generowanie HTML kończyło się błędem.

## 0.2

- Wersja wyjściowa.
