#!/usr/bin/env python3
"""
WebScan DK – Sårbarhedsscanner
Brug kun på systemer du ejer eller har skriftlig tilladelse til at teste.
"""

import asyncio
import ssl
import socket
import argparse
import sys
from datetime import datetime
from urllib.parse import urlparse

try:
    import httpx
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    print("Manglende afhængigheder. Kør: pip install httpx colorama")
    sys.exit(1)

# ─── 3 niveauer: KRITISK / ADVARSEL / INFO ────────────────────────────────────
#
#   KRITISK  = faktisk eksponeret data eller reel angrebsflade
#   ADVARSEL = manglende hardening, bør fixes men ikke direkte udnyttelig
#   INFO     = observationer, ikke problemer
#
NIVEAU_FARVE = {
    "KRITISK":  Fore.RED,
    "ADVARSEL": Fore.YELLOW,
    "INFO":     Fore.CYAN,
}
NIVEAU_RANG = {"KRITISK": 2, "ADVARSEL": 1, "INFO": 0}

fund = []

def tilføj(kategori, niveau, besked, detalje=""):
    fund.append({"kategori": kategori, "niveau": niveau, "besked": besked, "detalje": detalje})

def farve(tekst, f):
    return f"{f}{tekst}{Style.RESET_ALL}"

def niveau_label(n):
    return farve(f"[{n}]", NIVEAU_FARVE.get(n, Fore.WHITE))


# ─── Indholdsvalidering ───────────────────────────────────────────────────────
# Bruges til at bekræfte at en 200-respons faktisk indeholder det farlige indhold
# og ikke bare en fejlside eller login-redirect der tilfældigvis returnerer 200.

INDHOLD_SIGNATURER = {
    "/.env":          ["DB_PASSWORD", "APP_KEY", "SECRET", "DATABASE_URL", "MAIL_PASSWORD"],
    "/.git/config":   ["[core]", "[remote", "repositoryformatversion"],
    "/wp-config.php": ["DB_NAME", "DB_USER", "DB_PASSWORD", "table_prefix"],
    "/config.php":    ["password", "db_", "mysqli", "PDO"],
    "/phpinfo.php":   ["PHP Version", "phpinfo()", "PHP License"],
    "/server-status": ["Apache Server Status", "requests currently being processed"],
    "/server-info":   ["Apache Server Information", "Server Version"],
    "/.htaccess":     ["RewriteEngine", "AuthType", "Require", "Options"],
    "/backup.zip":    [],   # binær fil – 200 er nok
    "/backup.sql":    ["INSERT INTO", "CREATE TABLE", "DROP TABLE", "mysqldump"],
    "/db.sql":        ["INSERT INTO", "CREATE TABLE", "DROP TABLE"],
    "/phpMyAdmin":    ["phpMyAdmin", "pma_"],
    "/swagger":       ["swagger", "openapi", "Swagger UI"],
    "/swagger-ui.html": ["swagger-ui", "Swagger"],
    "/actuator":      ["_links", "health", "info"],
}

def bekræft_eksponering(sti, statuskode, indhold):
    """
    Returnerer True kun hvis der er reel grund til at markere stien som kritisk.
    Logik: 200 + indhold matcher signatur = eksponeret.
           403 = blokeret, ikke eksponeret. Ignoreres eller INFO.
           200 uden signatur-match = muligvis fejlside, sættes til ADVARSEL i stedet.
    """
    if statuskode == 403:
        return False  # serveren siger nej – ikke en lækage
    if statuskode != 200:
        return False

    signaturer = INDHOLD_SIGNATURER.get(sti, [])
    if not signaturer:
        return True  # binære filer – 200 er tilstrækkeligt signal

    return any(sig.lower() in indhold.lower() for sig in signaturer)


# ─── Tjek: Sikkerhedshoveder ──────────────────────────────────────────────────

async def tjek_hoveder(klient, url):
    try:
        r = await klient.get(url, follow_redirects=True, timeout=8)
    except Exception as e:
        tilføj("Netværk", "KRITISK", f"Kunne ikke nå målet: {e}")
        return None

    h = r.headers

    # Serverafsløring – kun INFO, ikke et angreb i sig selv
    server = h.get("server", "")
    if server:
        tilføj("Serverinfo", "INFO", f"Server-header eksponeret: {server}",
               "Afslører software-type, ikke kritisk alene")

    powered = h.get("x-powered-by", "")
    if powered:
        tilføj("Serverinfo", "INFO", f"X-Powered-By eksponeret: {powered}",
               "Afslører teknologi-stak, ikke kritisk alene")

    # Manglende hardening-headers – ADVARSEL, ikke KRITISK
    # De er anbefalede best practice, ikke direkte udnyttelige huller
    headers_tjek = {
        "x-frame-options":           "Mangler X-Frame-Options (clickjacking-beskyttelse)",
        "content-security-policy":   "Mangler Content-Security-Policy (CSP)",
        "strict-transport-security": "Mangler HSTS-header",
        "x-content-type-options":    "Mangler X-Content-Type-Options",
        "referrer-policy":           "Mangler Referrer-Policy",
        "permissions-policy":        "Mangler Permissions-Policy",
    }
    for header, besked in headers_tjek.items():
        if not h.get(header):
            tilføj("Manglende header", "ADVARSEL", besked,
                   "Manglende hardening – ikke direkte udnyttelig, men bør tilføjes")

    # CORS – kun KRITISK hvis wildcard OG credentials tillades
    acao = h.get("access-control-allow-origin", "")
    acac = h.get("access-control-allow-credentials", "")
    if acao == "*" and acac.lower() == "true":
        tilføj("CORS", "KRITISK", "CORS: wildcard origin + credentials=true",
               "Tillader ethvert site at sende autentificerede requests – reel angrebsflade")
    elif acao == "*":
        tilføj("CORS", "ADVARSEL", "CORS tillader alle oprindelser (Access-Control-Allow-Origin: *)",
               "Kan være intentionelt for public API'er – vurdér i kontekst")
    elif acao:
        tilføj("CORS", "INFO", f"CORS konfigureret for specifik origin: {acao}")

    # Cookies – kun KRITISK hvis session-cookie mangler flag
    rå_cookies = [v for k, v in r.headers.items() if k.lower() == "set-cookie"]
    for cookie in rå_cookies:
        cnavn = cookie.split("=")[0].strip()
        flag = cookie.lower()
        er_session = any(x in cnavn.lower() for x in ["session", "token", "auth", "login", "sid"])

        if "httponly" not in flag:
            niveau = "KRITISK" if er_session else "ADVARSEL"
            tilføj("Cookie", niveau,
                   f"Cookie '{cnavn}' mangler HttpOnly-flag",
                   "Session-cookie læsbar via JavaScript/XSS" if er_session else "Ikke-session cookie")
        if "secure" not in flag:
            niveau = "KRITISK" if er_session else "ADVARSEL"
            tilføj("Cookie", niveau,
                   f"Cookie '{cnavn}' mangler Secure-flag",
                   "Session-cookie sendes over ukrypteret HTTP" if er_session else "Ikke-session cookie")
        if "samesite" not in flag:
            tilføj("Cookie", "ADVARSEL",
                   f"Cookie '{cnavn}' mangler SameSite-flag",
                   "CSRF-risiko afhænger af applikationens logik")

    return r


# ─── Tjek: SSL/TLS ────────────────────────────────────────────────────────────

async def tjek_ssl(hostnavn, port=443):
    """
    Bruger certifi hvis tilgængeligt, ellers system-certs.
    En verify-fejl er en lokal setup-fejl og rapporteres som sådan.
    """
    try:
        import certifi
        cafile = certifi.where()
    except ImportError:
        cafile = None

    try:
        ctx = ssl.create_default_context(cafile=cafile)
        forbindelse = ctx.wrap_socket(socket.socket(), server_hostname=hostnavn)
        forbindelse.settimeout(5)
        forbindelse.connect((hostnavn, port))
        cert = forbindelse.getpeercert()
        forbindelse.close()

        udløb_str = cert.get("notAfter", "")
        if udløb_str:
            udløb = datetime.strptime(udløb_str, "%b %d %H:%M:%S %Y %Z")
            dage = (udløb - datetime.utcnow()).days
            if dage < 0:
                tilføj("SSL/TLS", "KRITISK", f"Certifikat udløbet for {abs(dage)} dage siden")
            elif dage < 14:
                tilføj("SSL/TLS", "KRITISK", f"Certifikat udløber om {dage} dage")
            elif dage < 30:
                tilføj("SSL/TLS", "ADVARSEL", f"Certifikat udløber om {dage} dage")
            else:
                tilføj("SSL/TLS", "INFO", f"Certifikat gyldigt i {dage} dage")

        # TLS 1.0
        try:
            svag = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            svag.check_hostname = False
            svag.verify_mode = ssl.CERT_NONE
            svag.minimum_version = ssl.TLSVersion.TLSv1
            svag.maximum_version = ssl.TLSVersion.TLSv1
            sc = svag.wrap_socket(socket.socket(), server_hostname=hostnavn)
            sc.settimeout(3)
            sc.connect((hostnavn, port))
            sc.close()
            tilføj("SSL/TLS", "ADVARSEL", "TLSv1.0 accepteres",
                   "Forældet protokol – sårbar over for POODLE/BEAST-angreb")
        except:
            tilføj("SSL/TLS", "INFO", "TLSv1.0 afvises")

    except ssl.SSLCertVerificationError as e:
        # Dette er en lokal fejl, ikke nødvendigvis target's skyld
        tilføj("SSL/TLS", "ADVARSEL",
               "Certifikat-verificering fejlede (muligvis lokal cert-store fejl)",
               f"Kør: pip install certifi  |  Fejl: {str(e)[:80]}")
    except ConnectionRefusedError:
        tilføj("SSL/TLS", "INFO", "Ingen HTTPS på port 443")
    except Exception as e:
        tilføj("SSL/TLS", "INFO", f"SSL-tjek kunne ikke gennemføres: {str(e)[:80]}")


# ─── Tjek: Følsomme stier ─────────────────────────────────────────────────────
# Kun KRITISK hvis: statuskode 200 OG indhold bekræfter eksponering
# 403 = ignoreres (serveren beskytter korrekt)
# 200 uden indholdsvalidering = ADVARSEL

async def tjek_stier(klient, basis_url):
    stier = [
        # (sti, besked ved eksponering, besked ved 200-uden-bekræftelse)
        ("/.env",               "Eksponeret .env-fil med credentials/API-nøgler"),
        ("/.git/config",        "Eksponeret .git-konfiguration – kildekode kan hentes"),
        ("/wp-config.php",      "Eksponeret WordPress-konfiguration med database-credentials"),
        ("/config.php",         "Eksponeret config.php med mulige credentials"),
        ("/phpinfo.php",        "phpinfo() tilgængelig – fuld serverinfo eksponeret"),
        ("/server-status",      "Apache server-status eksponeret"),
        ("/server-info",        "Apache server-info eksponeret"),
        ("/.htaccess",          "Eksponeret .htaccess-fil"),
        ("/backup.zip",         "backup.zip tilgængelig – potentiel fuld backup"),
        ("/backup.sql",         "backup.sql tilgængelig – potentielt databasedump"),
        ("/db.sql",             "db.sql tilgængelig – potentielt databasedump"),
        ("/phpMyAdmin",         "phpMyAdmin tilgængelig"),
        ("/swagger",            "Swagger UI eksponeret – API-dokumentation offentlig"),
        ("/swagger-ui.html",    "Swagger UI eksponeret"),
        ("/actuator",           "Spring Boot Actuator eksponeret"),
        ("/robots.txt",         "robots.txt tilgængelig"),
        ("/.well-known/security.txt", "security.txt tilgængelig"),
        ("/wp-admin",           "WordPress admin-panel tilgængeligt"),
        ("/admin",              "Admin-panel tilgængeligt"),
        ("/login",              "Login-side tilgængelig"),
    ]
    opgaver = [_sond_sti(klient, basis_url, sti, besked) for sti, besked in stier]
    await asyncio.gather(*opgaver)


async def _sond_sti(klient, basis_url, sti, besked):
    url = basis_url.rstrip("/") + sti
    try:
        r = await klient.get(url, follow_redirects=False, timeout=5)

        if r.status_code == 403:
            # Serveren beskytter ressourcen – ikke et fund
            return

        if r.status_code == 200:
            indhold = r.text[:4000]
            if bekræft_eksponering(sti, 200, indhold):
                tilføj("Eksponeret ressource", "KRITISK", besked,
                       f"HTTP 200 + indhold bekræftet → {sti}")
            else:
                # 200 men indhold matcher ikke – sandsynligvis fejlside/redirect
                tilføj("Mulig ressource", "ADVARSEL",
                       f"Sti svarer med 200 men indhold ikke bekræftet → {sti}",
                       "Kan være fejlside – tjek manuelt")

        elif r.status_code in (301, 302):
            lokation = r.headers.get("location", "")
            tilføj("Omdirigering", "INFO",
                   f"{sti} omdirigerer til {lokation}", f"HTTP {r.status_code}")

    except:
        pass


# ─── Tjek: Åben omdirigering ──────────────────────────────────────────────────

async def tjek_åben_omdirigering(klient, url):
    markør = "aaben-omdirigering-test.example"
    parametre = ["?next=", "?url=", "?redirect=", "?return=", "?goto="]
    for param in parametre:
        test_url = url.rstrip("/") + param + f"https://{markør}"
        try:
            r = await klient.get(test_url, follow_redirects=False, timeout=5)
            if r.status_code in (301, 302, 307, 308):
                lokation = r.headers.get("location", "")
                if markør in lokation:
                    tilføj("Åben omdirigering", "KRITISK",
                           f"Bekræftet åben omdirigering via parameter: {param}",
                           f"Omdirigerer til: {lokation}")
                    return
        except:
            pass


# ─── Tjek: WAF ────────────────────────────────────────────────────────────────

async def tjek_waf(klient, url):
    waf_signaturer = {
        "cloudflare":    "Cloudflare",
        "sucuri":        "Sucuri",
        "incapsula":     "Imperva/Incapsula",
        "x-amz-cf-id":  "AWS CloudFront",
        "x-cdn":         "CDN/WAF",
        "mod_security":  "ModSecurity",
        "x-firewall":    "Generisk firewall",
    }
    try:
        r = await klient.get(url, follow_redirects=True, timeout=8)
        header_str = " ".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
        for nøgle, navn in waf_signaturer.items():
            if nøgle in header_str:
                tilføj("WAF", "INFO", f"WAF/CDN detekteret: {navn}")
                return
        tilføj("WAF", "INFO",
               "Ingen WAF-signatur fundet i headers",
               "Kan stadig have firewall – dette er ikke en garanti")
    except:
        pass


# ─── Tjek: Porte ─────────────────────────────────────────────────────────────
# Port 80/443 er forventet og rapporteres ikke som fund.
# Kun uventede/farlige porte rapporteres.

async def tjek_porte(hostnavn):
    porte = {
        21:    ("FTP",        "ADVARSEL", "FTP åben – ukrypteret filoverførselsprotokol"),
        22:    ("SSH",        "INFO",     "SSH åben – forventet på de fleste servere"),
        23:    ("Telnet",     "KRITISK",  "Telnet åben – fuldstændig ukrypteret fjernadgang"),
        25:    ("SMTP",       "INFO",     "SMTP åben"),
        3306:  ("MySQL",      "KRITISK",  "MySQL direkte eksponeret til internettet"),
        5432:  ("PostgreSQL", "KRITISK",  "PostgreSQL direkte eksponeret til internettet"),
        6379:  ("Redis",      "KRITISK",  "Redis eksponeret – ingen autentificering som standard"),
        8080:  ("HTTP-alt",   "INFO",     "Alternativ HTTP-port åben (8080)"),
        8443:  ("HTTPS-alt",  "INFO",     "Alternativ HTTPS-port åben (8443)"),
        27017: ("MongoDB",    "KRITISK",  "MongoDB direkte eksponeret til internettet"),
        9200:  ("Elasticsearch", "KRITISK", "Elasticsearch eksponeret – typisk ingen auth som standard"),
    }
    print(farve("    Scanner porte", Fore.CYAN), end="", flush=True)
    opgaver = [_tjek_port(hostnavn, port, info) for port, info in porte.items()]
    await asyncio.gather(*opgaver)
    print()


async def _tjek_port(hostnavn, port, info):
    tjeneste, niveau, besked = info
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(hostnavn, port), timeout=2
        )
        writer.close()
        try:
            await writer.wait_closed()
        except:
            pass
        tilføj("Port", niveau, besked, f"port {port}/{tjeneste}")
        print(farve(".", Fore.GREEN if niveau == "INFO" else Fore.RED), end="", flush=True)
    except:
        print(farve(".", Fore.WHITE), end="", flush=True)


# ─── HTTP→HTTPS ───────────────────────────────────────────────────────────────

async def tjek_http_omdirigering(klient, url):
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return
    http_url = "http://" + parsed.netloc + (parsed.path or "/")
    try:
        r = await klient.get(http_url, follow_redirects=False, timeout=5)
        if r.status_code in (301, 302, 307, 308):
            lokation = r.headers.get("location", "")
            if lokation.startswith("https://"):
                tilføj("HTTPS", "INFO", "HTTP omdirigerer korrekt til HTTPS")
            else:
                tilføj("HTTPS", "ADVARSEL",
                       f"HTTP omdirigerer ikke til HTTPS (til: {lokation})")
        else:
            tilføj("HTTPS", "ADVARSEL",
                   f"HTTP omdirigerer ikke til HTTPS (statuskode: {r.status_code})")
    except:
        pass


# ─── Rapport ──────────────────────────────────────────────────────────────────

def udskriv_rapport(url, start_tid):
    varighed = (datetime.now() - start_tid).total_seconds()
    sorterede = sorted(fund, key=lambda x: NIVEAU_RANG.get(x["niveau"], 0), reverse=True)

    print(f"\n{farve('═'*60, Fore.CYAN)}")
    print(farve("  SCANNINGSRESULTATER", Fore.WHITE))
    print(farve(f"  Mål:      {url}", Fore.WHITE))
    print(farve(f"  Varighed: {varighed:.1f}s  |  Fund: {len(fund)}", Fore.WHITE))
    print(farve('═'*60, Fore.CYAN))

    if not sorterede:
        print(farve("\n  Ingen fund.", Fore.GREEN))
    else:
        nuværende = None
        for i, f_ in enumerate(sorterede, 1):
            if f_["niveau"] != nuværende:
                nuværende = f_["niveau"]
                print(f"\n  {niveau_label(nuværende)}")
                print(farve("  " + "─"*50, Fore.WHITE))
            print(f"  {str(i).rjust(3)}. {farve(f_['kategori'], Fore.WHITE)}  –  {f_['besked']}")
            if f_["detalje"]:
                print(farve(f"       ↳ {f_['detalje']}", Fore.WHITE))

    tæller = {k: sum(1 for f_ in fund if f_["niveau"] == k) for k in NIVEAU_RANG}
    print(f"\n{farve('─'*60, Fore.CYAN)}")
    for n in ["KRITISK", "ADVARSEL", "INFO"]:
        if tæller.get(n, 0):
            print(f"  {niveau_label(n):30}  {tæller[n]}")
    print(farve('═'*60, Fore.CYAN))


def gem_rapport(url):
    hostnavn = urlparse(url).netloc.replace(".", "_")
    filnavn = f"rapport_{hostnavn}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    sorterede = sorted(fund, key=lambda x: NIVEAU_RANG.get(x["niveau"], 0), reverse=True)
    linjer = [
        "WebScan DK – Sårbarhedsrapport",
        f"Mål: {url}",
        f"Tidspunkt: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}",
        "=" * 60, "",
    ]
    for i, f_ in enumerate(sorterede, 1):
        linjer.append(f"[{i}] [{f_['niveau']}] {f_['kategori']} – {f_['besked']}")
        if f_["detalje"]:
            linjer.append(f"     {f_['detalje']}")
        linjer.append("")
    with open(filnavn, "w", encoding="utf-8") as fp:
        fp.write("\n".join(linjer))
    print(farve(f"\n  Rapport gemt: {filnavn}", Fore.GREEN))


# ─── Hoved ────────────────────────────────────────────────────────────────────

async def hoved(url, gem, spring_porte_over):
    start_tid = datetime.now()
    parsed = urlparse(url)
    hostnavn = parsed.netloc

    print(farve("═" * 60, Fore.CYAN))
    print(farve("  WEBSCAN DK", Fore.YELLOW))
    print(farve("  Brug kun på systemer du har tilladelse til at teste!", Fore.RED))
    print(farve("═" * 60, Fore.CYAN))
    print(f"\n  {farve('Mål:', Fore.WHITE)} {farve(url, Fore.YELLOW)}\n")

    grænser = httpx.Limits(max_connections=20, max_keepalive_connections=10)
    async with httpx.AsyncClient(
        verify=False,
        timeout=10,
        limits=grænser,
        headers={"User-Agent": "WebScanDK/1.0 (autoriseret sikkerhedstest)"}
    ) as klient:

        print(farve("  [1/5] Hoveder, cookies og CORS...", Fore.CYAN))
        await tjek_hoveder(klient, url)

        print(farve("  [2/5] SSL/TLS-certifikat...", Fore.CYAN))
        if parsed.scheme == "https":
            await tjek_ssl(hostnavn)
        else:
            tilføj("SSL/TLS", "ADVARSEL", "Siden bruger HTTP – ingen kryptering")

        print(farve("  [3/5] Følsomme stier (kun 200 tæller)...", Fore.CYAN))
        await tjek_stier(klient, url)

        print(farve("  [4/5] HTTP-omdirigering, åben redirect og WAF...", Fore.CYAN))
        await asyncio.gather(
            tjek_http_omdirigering(klient, url),
            tjek_åben_omdirigering(klient, url),
            tjek_waf(klient, url),
        )

        if not spring_porte_over:
            print(farve("  [5/5] Portscanning...", Fore.CYAN))
            await tjek_porte(hostnavn)
        else:
            print(farve("  [5/5] Portscanning sprunget over.", Fore.WHITE))

    udskriv_rapport(url, start_tid)
    if gem:
        gem_rapport(url)


def main():
    parser = argparse.ArgumentParser(
        description="WebScan DK – Sårbarhedsscanner",
        epilog="Eksempel:\n  python vuln_scanner_da.py https://eksempel.dk --gem"
    )
    parser.add_argument("url", nargs="?", help="URL der skal scannes")
    parser.add_argument("--gem",         action="store_true", help="Gem rapport til .txt")
    parser.add_argument("--ingen-porte", action="store_true", help="Spring portscanning over")
    args = parser.parse_args()

    url = args.url
    if not url:
        print(farve("\n  WebScan DK – Sårbarhedsscanner", Fore.YELLOW))
        print(farve("  Kun til systemer du har tilladelse til at teste!\n", Fore.RED))
        url = input("  Indtast URL: ").strip()

    if not url:
        sys.exit(1)
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    import warnings
    warnings.filterwarnings("ignore")

    asyncio.run(hoved(url, args.gem, args.ingen_porte))


if __name__ == "__main__":
    main()