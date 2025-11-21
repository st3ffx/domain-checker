# 🛠️ domaincheck – Umfangreicher Domain-, DNS- & Mail-Checker (Deutsch)

`domaincheck` ist ein leistungsstarkes Kommandozeilen-Tool in Python zur Analyse von Domains:

- DNS Records  
- SPF (inkl. rekursiver Analyse & DNS-Lookup-Zählung, Warnung bei > 10 Lookups)  
- DMARC  
- DKIM (Standard-Selektoren)  
- BIMI  
- DNSSEC  
- WHOIS  
- TLS/SSL-Zertifikat  
- HTTP/HTTPS & Security-Header  
- einfache Subdomain-Erkennung  
- AXFR / Zonentransfer-Test  
- DNSBL (Spamhaus, Barracuda, SpamCop, UCEPROTECT, usw.)  
- Reverse DNS (PTR) für Domain-IP & MX-Server  

Alle Meldungen werden in deutscher Sprache ausgegeben:  
`[OK]`, `[WARNUNG]`, `[FEHLER]`, `[INFO]`

---

## 🚀 Installation (empfohlen per Einzeiler)

```bash
bash <(wget -qO- https://raw.githubusercontent.com/st3ffx/domain-checker/main/install.sh)
