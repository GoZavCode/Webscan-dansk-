# Webscan-dansk

Dansk sårbarhedsscanner til hjemmesider. Tjekker sikkerhedshoveder, SSL/TLS, cookies, CORS, følsomme stier og åbne porte. Skelner mellem reelle eksponeringer og false positives.

> **Brug kun på systemer du ejer eller har skriftlig tilladelse til at teste.**

## Installation

```bash
pip install httpx colorama
```

Valgfrit men anbefalet for korrekt SSL-verifikation:

```bash
pip install certifi
```

## Brug

```bash
python vuln_scanner_da.py https://eksempel.dk
```

Gem rapport til fil:

```bash
python vuln_scanner_da.py https://eksempel.dk --gem
```

Spring portscanning over:

```bash
python vuln_scanner_da.py https://eksempel.dk --ingen-porte
```

## Hvad den tjekker

- Sikkerhedshoveder (CSP, HSTS, X-Frame-Options m.fl.)
- SSL/TLS-certifikat (udløb, svage protokoller)
- Cookie-flag (HttpOnly, Secure, SameSite)
- CORS-fejlkonfiguration
- Følsomme stier og filer (.env, .git, backups, adminpaneler osv.)
- HTTP→HTTPS-omdirigering
- Åben omdirigering
- WAF-detektion
- Portscanning (MySQL, Redis, MongoDB, Telnet osv.)

## Niveauer

| Niveau | Betyder |
|--------|---------|
| KRITISK | Faktisk eksponeret data eller reel angrebsflade |
| ADVARSEL | Manglende hardening – bør fixes, ikke direkte udnyttelig |
| INFO | Observationer |

Scriptet tæller **ikke** 403-svar som fund. En sti markeres kun som KRITISK hvis HTTP 200 returneres **og** indholdet bekræfter eksponeringen.

## Krav

- Python 3.8+
- httpx
- colorama
