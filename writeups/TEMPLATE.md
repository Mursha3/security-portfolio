# <Krótki tytuł — co, gdzie i jaki efekt>

> Skopiuj ten plik do `writeups/RRRR-MM-DD-krotki-slug.md` i wypełnij.
> Sekcje, które nie pasują, usuń — ale nie zostawiaj pustych nagłówków.

| | |
| --- | --- |
| **Data zgłoszenia** | RRRR-MM-DD |
| **Data publikacji** | RRRR-MM-DD (albo `niepublikowane`) |
| **Zgłoszone do** | vendor / CERT Polska / GHSA / program bug bounty |
| **Status** | zgłoszone / potwierdzone / naprawione / odrzucone / duplikat |
| **ID** | CVE-XXXX-YYYYY / GHSA-xxxx-xxxx / wewnętrzny numer |
| **Podatny zakres** | wersje, buildy, konfiguracje |
| **Wpływ** | jedna linia: co atakujący realnie uzyskuje |
| **CVSS** | wektor + score (tylko jeśli liczysz, nie zgaduj) |

## Podsumowanie

Dwa, trzy akapity. Co to za produkt, jaka klasa podatności, dlaczego ma
znaczenie. Bez dramaturgii, bez "hackerman".

## Warunki brzegowe

- Wersja produktu i dokładna konfiguracja testu.
- Środowisko (system, wersja biblioteki, co było włączone).
- Co było **poza** zakresem.

## Kroki reprodukcji

Numerowane, kompletne. Ktoś, kto nie pisał tego raportu, ma dojść do tego
samego wyniku.

1. Postaw `...` w wersji `...`:

   ```bash
   docker run --rm -p 8080:8080 vendor/product:1.2.3
   ```

2. Wyślij żądanie:

   ```http
   POST /api/export HTTP/1.1
   Host: localhost:8080
   Content-Type: application/json

   {"path": "../../etc/passwd"}
   ```

3. Oczekiwany wynik — wklej **dowód**, nie opis dowodu:

   ```
   root:x:0:0:root:/root:/bin/bash
   ```

## Analiza przyczyny

Dlaczego to działa. Konkretna funkcja, linia, brak walidacji, kolejność
sprawdzeń. To jest sekcja, która odróżnia raport od screenshotów.

```python
# podatny fragment, skrócony do minimum
```

## Wpływ

- Co może zrobić atakujący i z jakimi uprawnieniami.
- Czy wymaga uwierzytelnienia, interakcji użytkownika, dostępu sieciowego.
- Kto realnie jest zagrożony.

## Naprawa

- **Dla dostawcy:** co zmienić w kodzie/konfiguracji.
- **Dla użytkownika:** obejście lub mitigacja, dopóki nie ma patcha.

## Oś czasu

| Data | Zdarzenie |
| --- | --- |
| RRRR-MM-DD | Wykrycie i weryfikacja własnym PoC |
| RRRR-MM-DD | Zgłoszenie do dostawcy (`security@...` / formularz) |
| RRRR-MM-DD | Potwierdzenie od dostawcy |
| RRRR-MM-DD | Publikacja poprawki |
| RRRR-MM-DD | Publikacja tego writeupu |

## Źródła

- [Advisory dostawcy](https://example.com/advisory)
- [Dokumentacja / kod](https://example.com/src)

---

## Wariant: writeup CTF-owy

Do tego samego pliku, w skróconej formie:

```markdown
# <Nazwa zadania> — <kategoria>, <punkty> pkt
## Treść zadania
## Rozpoznanie
## Rozwiązanie
## Flaga: CTF{dokładny_string_jeśli_regulamin_na_to_pozwala}
## Czego się nauczyłem
```

Sprawdź regulamin CTF-a, zanim publikujesz flagę albo pełne rozwiązanie.
Zadania z aktywnych, powtarzalnych konkursów zostaw jako notatkę bez flagi.
