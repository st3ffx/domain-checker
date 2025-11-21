#!/usr/bin/env python3
import sys
import socket
import ssl
import datetime
import subprocess
import http.client

import dns.resolver
import dns.exception
import dns.query
import dns.zone
import dns.reversename  # für PTR / rDNS

# Farb-Codes für die Ausgabe
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_RED = "\033[91m"
COLOR_RESET = "\033[0m"

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV", "CAA"]

resolver = dns.resolver.Resolver()
resolver.timeout = 3
resolver.lifetime = 3


def color(prefix, msg, color_code):
    return f"{color_code}{prefix}{COLOR_RESET} {msg}"


def info(msg):
    print(color("[INFO]", msg, COLOR_YELLOW))


def ok(msg):
    print(color("[OK]", msg, COLOR_GREEN))


def warn(msg):
    print(color("[WARNUNG]", msg, COLOR_YELLOW))


def error(msg):
    print(color("[FEHLER]", msg, COLOR_RED))


def print_section(title):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def query_records(domain, rtype):
    try:
        answers = resolver.resolve(domain, rtype)
        return [str(rdata.to_text()) for rdata in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    except Exception as e:
        return [f"FEHLER: {e}"]


def get_first_ipv4(domain):
    records = query_records(domain, "A")
    for r in records:
        if not r.startswith("FEHLER"):
            return r.split()[0]
    return None


def resolve_all_dns(domain):
    print_section(f"DNS-Einträge für: {domain}")
    all_records = {}
    for rtype in RECORD_TYPES:
        recs = query_records(domain, rtype)
        all_records[rtype] = recs
        print(f"\n[{rtype}]")
        if recs:
            for r in recs:
                print(f"  {r}")
        else:
            print("  (keine Einträge gefunden)")
    return all_records


# ---------- SPF-Analyse (erweitert & rekursiv) ----------

def fetch_spf_record(domain):
    """Erster TXT-Eintrag mit 'v=spf1' für eine Domain."""
    txts = query_records(domain, "TXT")
    for t in txts:
        if "v=spf1" in t:
            return t
    return None


def clean_spf_string(spf_raw):
    """Entfernt Anführungszeichen und normalisiert Leerzeichen."""
    if not spf_raw:
        return ""
    s = spf_raw.replace('"', " ").strip()
    while "  " in s:
        s = s.replace("  ", " ")
    return s


def analyze_spf_domain(domain, visited=None, depth=0):
    """
    Rekursive SPF-Analyse:
    - zählt DNS-Lookups (include, redirect, a, mx, ptr, exists)
    - folgt includes/redirects rekursiv
    """
    indent = "  " * depth
    if visited is None:
        visited = set()
    details = []

    if domain in visited:
        details.append(f"{indent}SPF-Zyklus erkannt bei {domain}, weitere Rekursion abgebrochen.")
        return 0, details

    visited.add(domain)

    spf_raw = fetch_spf_record(domain)
    if not spf_raw:
        details.append(f"{indent}Kein SPF-Eintrag für {domain} gefunden.")
        return 0, details

    spf = clean_spf_string(spf_raw)
    details.append(f"{indent}SPF für {domain}: {spf}")

    lookups = 0
    parts = spf.split()

    for part in parts:
        if part.lower().startswith("v=spf1"):
            continue

        qualifier = ""
        mech = part
        if mech and mech[0] in ["+", "-", "~", "?"]:
            qualifier = mech[0]
            mech = mech[1:]

        if mech == "all" or mech.endswith("all"):
            continue

        if mech.startswith("include:"):
            inc_domain = mech.split(":", 1)[1]
            lookups += 1
            details.append(f"{indent}include:{inc_domain} -> 1 DNS-Lookup (TXT für SPF)")
            sub_lookups, sub_details = analyze_spf_domain(inc_domain, visited, depth + 1)
            lookups += sub_lookups
            details.extend(sub_details)
            continue

        if mech.startswith("redirect="):
            red_domain = mech.split("=", 1)[1]
            lookups += 1
            details.append(f"{indent}redirect={red_domain} -> 1 DNS-Lookup (TXT für SPF)")
            sub_lookups, sub_details = analyze_spf_domain(red_domain, visited, depth + 1)
            lookups += sub_lookups
            details.extend(sub_details)
            continue

        if mech.startswith("a"):
            lookups += 1
            details.append(f"{indent}{qualifier + 'a'}-Mechanismus -> 1 DNS-Lookup (A/AAAA)")
            continue

        if mech.startswith("mx"):
            lookups += 1
            details.append(f"{indent}{qualifier + 'mx'}-Mechanismus -> 1 DNS-Lookup (MX + A/AAAA)")
            continue

        if mech.startswith("ptr"):
            lookups += 1
            details.append(f"{indent}{qualifier + 'ptr'}-Mechanismus -> 1 DNS-Lookup (PTR)")
            continue

        if mech.startswith("exists:"):
            lookups += 1
            details.append(f"{indent}{qualifier + 'exists'}-Mechanismus -> 1 DNS-Lookup (EXISTS)")
            continue

    return lookups, details


# ---------- Ende SPF-Analyse ----------


def check_email_security(domain, records):
    print_section("E-Mail-/DNS-Sicherheit (SPF, DMARC, DKIM, BIMI)")

    mx_recs = records.get("MX", []) or []
    has_mx = len(mx_recs) > 0
    if not has_mx:
        warn("Keine MX-Einträge vorhanden – die Domain empfängt vermutlich keine E-Mails.")
    else:
        ok("MX-Einträge vorhanden.")
        print("\nMX-Hosts überprüfen...")
        for mx in mx_recs:
            parts = mx.split()
            if len(parts) == 2:
                mx_host = parts[1].rstrip(".")
            else:
                mx_host = mx.rstrip(".")
            a_recs = query_records(mx_host, "A")
            aaaa_recs = query_records(mx_host, "AAAA")
            if not a_recs and not aaaa_recs:
                warn(f"MX-Host '{mx_host}' hat keinen A- oder AAAA-Eintrag.")
            else:
                ok(f"MX-Host '{mx_host}' hat gültige A/AAAA-Einträge.")

    # SPF – Existenz + erweiterte Analyse
    txt_recs = records.get("TXT", []) or []
    spf_records = [t for t in txt_recs if "v=spf1" in t]

    if has_mx:
        if not spf_records:
            warn("Keine SPF-Einträge gefunden (TXT mit 'v=spf1'), obwohl MX vorhanden ist.")
        elif len(spf_records) > 1:
            warn("Mehrere SPF-Einträge gefunden. Es darf nur EIN SPF-Eintrag existieren.")
            spf_domain = domain
            total_lookups, details = analyze_spf_domain(spf_domain)
            print("\nSPF-Detailanalyse (trotz Mehrfach-Konfiguration):")
            for line in details:
                print("  " + line)
            print(f"\nGesamtanzahl geschätzter SPF-DNS-Lookups: {total_lookups}")
            if total_lookups > 10:
                error(f"SPF verletzt die 10-DNS-Lookup-Grenze (insgesamt {total_lookups} Lookups).")
            else:
                ok(f"SPF-DNS-Lookups innerhalb des Limits (insgesamt {total_lookups} Lookups).")
        else:
            ok("SPF-Eintrag vorhanden.")
            spf_domain = domain
            total_lookups, details = analyze_spf_domain(spf_domain)
            print("\nSPF-Detailanalyse:")
            for line in details:
                print("  " + line)
            print(f"\nGesamtanzahl geschätzter SPF-DNS-Lookups: {total_lookups}")
            if total_lookups > 10:
                error(f"SPF verletzt die 10-DNS-Lookup-Grenze (insgesamt {total_lookups} Lookups).")
            else:
                ok(f"SPF-DNS-Lookups innerhalb des von RFC empfohlenen Limits (insgesamt {total_lookups} Lookups).")
    else:
        info("Keine MX-Einträge – SPF/DMARC sind eventuell nicht notwendig.")

    # DMARC
    if has_mx:
        dmarc_domain = f"_dmarc.{domain}"
        dmarc_txt = query_records(dmarc_domain, "TXT")
        dmarc_records = [t for t in dmarc_txt if "v=DMARC1" in t]
        if not dmarc_records:
            warn(f"Kein DMARC-Eintrag gefunden unter {dmarc_domain}.")
        else:
            ok("DMARC-Eintrag vorhanden.")

    # DKIM (einfacher Check mit bekannten Selektoren)
    selectors = ["default", "google", "selector1", "selector2", "dkim"]
    found_dkim = False
    for sel in selectors:
        dkim_domain = f"{sel}._domainkey.{domain}"
        dkim_txt = query_records(dkim_domain, "TXT")
        if any("v=DKIM1" in t for t in dkim_txt):
            ok(f"DKIM-Eintrag gefunden mit Selector '{sel}'.")
            found_dkim = True
            break
    if not found_dkim:
        info("Kein DKIM-Eintrag mit Standard-Selektoren gefunden (default/google/selector1/selector2/dkim).")

    # BIMI
    bimi_domain = f"default._bimi.{domain}"
    bimi_txt = query_records(bimi_domain, "TXT")
    if any("v=BIMI1" in t for t in bimi_txt):
        ok("BIMI-Eintrag gefunden.")
    else:
        info("Kein BIMI-Eintrag gefunden (optional, nur für Marken/E-Mail-Branding).")


def check_dnssec(domain):
    print_section("DNSSEC-Status")
    try:
        ds_records = resolver.resolve(domain, "DS")
        if ds_records:
            ok("DNSSEC scheint aktiviert zu sein (DS-Einträge vorhanden).")
            for ds in ds_records:
                print(f"  {ds.to_text()}")
        else:
            warn("Keine DS-Einträge gefunden – DNSSEC ist wahrscheinlich nicht aktiviert.")
    except Exception:
        info("Keine DS-Einträge gefunden oder Resolver unterstützt diese Abfrage nicht – DNSSEC vermutlich nicht aktiv.")


def check_whois(domain):
    print_section("WHOIS-Informationen")
    try:
        result = subprocess.run(
            ["whois", domain],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode != 0 or not result.stdout.strip():
            warn("Konnte WHOIS-Informationen nicht abrufen (whois-Tool installiert?).")
            return
        data = result.stdout
        lines = data.splitlines()
        exp = None
        registrar = None
        for line in lines:
            low = line.lower()
            if "registrar" in low and not registrar and ":" in line:
                registrar = line.split(":", 1)[1].strip()
            if ("expir" in low or "valid until" in low or "renewal date" in low) and ":" in line:
                exp = line.split(":", 1)[1].strip()
        if registrar:
            ok(f"Registrar: {registrar}")
        else:
            info("Registrar konnte aus WHOIS-Daten nicht eindeutig erkannt werden.")
        if exp:
            ok(f"Ablaufdatum (WHOIS): {exp}")
        else:
            info("Ablaufdatum konnte aus WHOIS-Daten nicht eindeutig erkannt werden.")
    except FileNotFoundError:
        warn("Das 'whois'-Kommando ist nicht installiert. WHOIS-Check wird übersprungen.")
    except subprocess.TimeoutExpired:
        warn("WHOIS-Abfrage hat zu lange gedauert und wurde abgebrochen.")
    except Exception as e:
        warn(f"Fehler bei WHOIS-Abfrage: {e}")


def check_ssl(domain):
    print_section("TLS/SSL-Zertifikat (Port 443)")
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
    except Exception as e:
        warn(f"Keine TLS-Verbindung zu {domain}:443 möglich: {e}")
        return

    subject = dict(x[0] for x in cert.get("subject", []))
    issued_to = subject.get("commonName", "")
    issuer = dict(x[0] for x in cert.get("issuer", []))
    issued_by = issuer.get("commonName", "")

    not_before = cert.get("notBefore")
    not_after = cert.get("notAfter")

    print(f"Zertifikat ausgestellt für: {issued_to}")
    print(f"Ausgestellt von:          {issued_by}")
    print(f"Gültig von:               {not_before}")
    print(f"Gültig bis:               {not_after}")

    if not_after:
        try:
            exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (exp - datetime.datetime.utcnow()).days
            if days_left < 0:
                warn(f"Zertifikat ist abgelaufen (seit {-days_left} Tagen).")
            elif days_left < 14:
                warn(f"Zertifikat läuft bald ab (in {days_left} Tagen).")
            else:
                ok(f"Zertifikat ist gültig, noch ca. {days_left} Tage.")
        except Exception:
            info("Konnte Ablaufdatum des Zertifikats nicht auswerten.")


def check_http(domain):
    print_section("HTTP/HTTPS & Security-Header")

    def fetch(use_https=True):
        port = 443 if use_https else 80
        conn = None
        try:
            if use_https:
                conn = http.client.HTTPSConnection(domain, port, timeout=5)
            else:
                conn = http.client.HTTPConnection(domain, port, timeout=5)
            conn.request("GET", "/")
            resp = conn.getresponse()
            headers = dict(resp.getheaders())
            _ = resp.read(0)
            return resp.status, headers
        except Exception as e:
            return None, {"_error": str(e)}
        finally:
            if conn:
                conn.close()

    status, headers = fetch(use_https=True)
    if status is None:
        warn(f"HTTPS (443) konnte nicht abgefragt werden: {headers.get('_error')}")
        status_http, headers_http = fetch(use_https=False)
        if status_http is None:
            warn(f"HTTP (80) konnte nicht abgefragt werden: {headers_http.get('_error')}")
            return
        else:
            info(f"HTTP-Antwort (ohne TLS): Status {status_http}")
            used_headers = headers_http
    else:
        ok(f"HTTPS-Antwort erhalten: Status {status}")
        used_headers = headers

    server = used_headers.get("Server") or used_headers.get("server")
    if server:
        info(f"Webserver: {server}")

    def check_header(name, critical=True):
        val = used_headers.get(name) or used_headers.get(name.lower())
        if val:
            ok(f"Security-Header vorhanden: {name} = {val}")
        else:
            if critical:
                warn(f"Security-Header fehlt: {name}")
            else:
                info(f"Security-Header fehlt (optional): {name}")

    check_header("Strict-Transport-Security")
    check_header("Content-Security-Policy")
    check_header("X-Frame-Options")
    check_header("X-Content-Type-Options")
    check_header("Referrer-Policy", critical=False)
    check_header("Permissions-Policy", critical=False)


def check_subdomains(domain):
    print_section("Einfache Subdomain-Prüfung")
    subdomains = [
        "www", "mail", "ftp", "api", "smtp",
        "imap", "pop", "pop3", "autodiscover", "webmail"
    ]
    for sub in subdomains:
        fqdn = f"{sub}.{domain}"
        a_recs = query_records(fqdn, "A")
        if a_recs:
            ok(f"Subdomain gefunden: {fqdn} -> {', '.join(a_recs)}")


def check_axfr(domain, ns_records):
    print_section("AXFR / Zonentransfer-Test")
    if not ns_records:
        info("Keine Nameserver-Einträge, AXFR-Test übersprungen.")
        return
    for ns in ns_records:
        ns_host = ns.rstrip(".")
        info(f"Teste Zonentransfer von Nameserver: {ns_host}")
        try:
            xfr = dns.query.xfr(ns_host, domain, timeout=5)
            zone = dns.zone.from_xfr(xfr)
            if zone:
                warn(f"Zonentransfer (AXFR) bei {ns_host} ERLAUBT – großes Sicherheitsrisiko!")
                return
        except Exception:
            continue
    ok("Zonentransfer (AXFR) scheint bei allen Nameservern deaktiviert zu sein.")


def check_dnsbl(domain):
    print_section("DNSBL / Blacklist-Check (erweitert)")
    ip = get_first_ipv4(domain)
    if not ip:
        warn("Keine IPv4-Adresse gefunden – DNSBL-Check übersprungen.")
        return
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            warn(f"Ungültige IPv4-Adresse für DNSBL-Check: {ip}")
            return
        reversed_ip = ".".join(reversed(parts))

        lists = [
            "zen.spamhaus.org",
            "b.barracudacentral.org",
            "bl.spamcop.net",
            "multi.surbl.org",
            "ivmSIP.invaluement.com",
            "ivmURI.invaluement.com",
            "dnsbl-1.uceprotect.net",
            "dnsbl-2.uceprotect.net",
            "dnsbl-3.uceprotect.net",
            "psbl.surriel.com",
            "black.junkemailfilter.com",
            "ubl.unsubscore.com",
            "all.spamrats.com",
            "dnsbl.0spam.org"
        ]

        info(f"DNSBL-Check für IP {ip} (reverse: {reversed_ip})")

        for bl in lists:
            query = f"{reversed_ip}.{bl}"
            try:
                _ = resolver.resolve(query, "A")
                warn(f"IP {ip} ist auf Blacklist {bl} GELISTET!")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                    dns.resolver.NoNameservers, dns.exception.Timeout):
                ok(f"IP {ip} ist NICHT auf {bl} gelistet.")
            except Exception as e:
                info(f"Fehler bei DNSBL-Check gegen {bl}: {e}")
    except Exception as e:
        warn(f"Fehler beim Verarbeiten der IP für DNSBL: {e}")


def basic_dns_checks(domain, records):
    print_section("Grundlegende DNS-Checks")
    has_a = bool(records.get("A"))
    has_aaaa = bool(records.get("AAAA"))
    has_cname = bool(records.get("CNAME"))
    if not (has_a or has_aaaa or has_cname):
        warn("Domain hat weder A-, AAAA- noch CNAME-Einträge – Webzugriff wahrscheinlich nicht möglich.")
    else:
        ok("Domain hat grundlegende Einträge für Web-Erreichbarkeit (A/AAAA/CNAME).")

    ns_records = records.get("NS", []) or []
    if not ns_records:
        warn("Keine NS-Einträge gefunden – DNS-Konfiguration scheint fehlerhaft.")
    else:
        if len(ns_records) < 2:
            warn("Weniger als 2 Nameserver konfiguriert – empfohlen sind mindestens zwei.")
        else:
            ok("Mindestens 2 Nameserver konfiguriert.")

        print("\nNameserver-IP-Auflösung:")
        for ns in ns_records:
            ns_host = ns.rstrip(".")
            a_recs = query_records(ns_host, "A")
            aaaa_recs = query_records(ns_host, "AAAA")
            if not a_recs and not aaaa_recs:
                warn(f"Nameserver '{ns_host}' hat keinen A- oder AAAA-Eintrag.")
            else:
                ok(f"Nameserver '{ns_host}' ist über A/AAAA erreichbar.")


# ---------- PTR / Reverse-DNS-Check ----------

def ptr_lookup(ip):
    try:
        rev = dns.reversename.from_address(ip)
        answers = resolver.resolve(rev, "PTR")
        return [str(r.to_text()) for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    except Exception:
        return []


def check_reverse_dns(domain, records):
    print_section("Reverse DNS / PTR-Records")

    # Haupt-IP des Domains
    ip = get_first_ipv4(domain)
    if ip:
        ptrs = ptr_lookup(ip)
        if ptrs:
            ok(f"PTR für Haupt-IP {ip}: {', '.join(ptrs)}")
        else:
            warn(f"Kein PTR-Eintrag für Haupt-IP {ip} gefunden.")
    else:
        warn("Keine IPv4-Adresse für Domain gefunden – PTR-Check für Haupt-IP übersprungen.")

    # PTR für MX-Hosts
    mx_recs = records.get("MX", []) or []
    if not mx_recs:
        info("Keine MX-Einträge – PTR-Check für Mailserver übersprungen.")
        return

    print("\nPTR-Checks für MX-Hosts:")
    for mx in mx_recs:
        parts = mx.split()
        if len(parts) == 2:
            mx_host = parts[1].rstrip(".")
        else:
            mx_host = mx.rstrip(".")
        a_recs = query_records(mx_host, "A")
        if not a_recs:
            warn(f"MX-Host {mx_host} hat keinen A-Eintrag – PTR nicht prüfbar.")
            continue
        for a in a_recs:
            ip = a.split()[0]
            ptrs = ptr_lookup(ip)
            if ptrs:
                ok(f"PTR für MX-IP {ip} ({mx_host}): {', '.join(ptrs)}")
            else:
                warn(f"Kein PTR für MX-IP {ip} ({mx_host}) gefunden – könnte für Mailzustellung problematisch sein.")


# ---------- MAIN ----------

def main():
    if len(sys.argv) != 2:
        print(f"Verwendung: {sys.argv[0]} domain.de")
        sys.exit(1)

    domain = sys.argv[1].strip()
    print_section(f"Gesamt-Check für Domain: {domain}")

    records = resolve_all_dns(domain)
    basic_dns_checks(domain, records)
    check_email_security(domain, records)
    check_dnssec(domain)
    check_whois(domain)
    check_ssl(domain)
    check_http(domain)
    check_subdomains(domain)
    check_axfr(domain, records.get("NS", []) or [])
    check_dnsbl(domain)
    check_reverse_dns(domain, records)

    print_section("Fertig")


if __name__ == "__main__":
    main()
