"""
KEVlar - Vendor risk pesato sul ransomware
==========================================
Legge il catalogo pubblico CISA KEV (Known Exploited Vulnerabilities: le
vulnerabilita' NOTE COME SFRUTTATE nel mondo reale) e produce una vista
"rischio per vendor" pensata per orientare le SCELTE di stack/perimetro e la
prioritizzazione delle patch - non solo per difendere.

Perche' non il conteggio grezzo
-------------------------------
Il numero di KEV per vendor e' una TRAPPOLA-POPOLARITA': i prodotti ubiqui
(Windows, Chrome, Linux) dominano la classifica perche' sono i piu' usati e
scrutinati, non perche' siano i peggiori. Il segnale di QUALITA' e' un altro:

- quante KEV finiscono ARMATE dal ransomware (campo knownRansomwareCampaignUse)
  e il loro RAPPORTO sul totale del vendor -> un tasso alto e' tipico di
  edge/appliance (VPN, firewall, gateway, NAS): la porta d'ingresso preferita;
- il TREND recente (KEV aggiunte negli ultimi mesi) -> chi "scotta" ora.

Dato pubblico CISA -> il report e' TLP:CLEAR (condivisibile senza restrizioni).

Uso:
    python kevlar.py                  # scarica il KEV da CISA e genera il report
    python kevlar.py --file kev.json  # usa un catalogo locale gia' scaricato
    python kevlar.py --no-download    # usa la cache locale se presente

Nessuna dipendenza esterna: solo libreria standard, Python 3.9+.

Autore: Manuel Carletti - https://www.linkedin.com/in/manuel-c-3b72b7125/
Licenza: MIT.
"""
import argparse
import collections
import datetime
import json
import urllib.request
from pathlib import Path

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
BASE_DIR = Path(__file__).resolve().parent
CACHE_PATH = BASE_DIR / "cisa_kev_catalog.json"
OUTPUT_DIR = BASE_DIR / "output"
MESI_TREND = 12
# Campione minimo di KEV per comparire nella classifica PER-TASSO: sotto questa
# soglia un ratio (es. 2 KEV entrambe ransomware = 100%) e' rumore statistico.
MIN_KEV_RATIO = 10


def scarica_kev(url=CISA_KEV_URL, cache=CACHE_PATH, timeout=30):
    """Scarica il catalogo CISA KEV (dato pubblico) in cache locale e ritorna il path."""
    req = urllib.request.Request(url, headers={"User-Agent": "KEVlar"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        dati = r.read()
    Path(cache).write_bytes(dati)
    return Path(cache)


def _campo(v, *nomi):
    for n in nomi:
        if v.get(n):
            return v[n]
    return ""


def carica_kev(path):
    """Ritorna (lista_vulnerabilita, versione_catalogo). Robusto al formato."""
    try:
        kev = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return [], "?"
    if isinstance(kev, list):
        return kev, "?"
    vulns = kev.get("vulnerabilities") or kev.get("cves") or []
    return vulns, kev.get("catalogVersion", "?")


def aggrega_vendor(vulns, oggi=None, mesi_trend=MESI_TREND):
    """Per ogni vendor: kev totali, ransomware-linked, recenti (ultimi N mesi),
    ratio ransomware/kev, prodotti. Ritorna {vendor: {...}}."""
    oggi = oggi or datetime.date.today()
    soglia_giorni = mesi_trend * 30
    agg = {}
    for v in vulns:
        vd = _campo(v, "vendorProject", "vendor") or "?"
        d = agg.setdefault(vd, {"kev": 0, "ransomware": 0, "recenti": 0,
                                "prodotti": collections.Counter()})
        d["kev"] += 1
        d["prodotti"][_campo(v, "product") or "?"] += 1
        if str(_campo(v, "knownRansomwareCampaignUse")).lower() == "known":
            d["ransomware"] += 1
        da = _campo(v, "dateAdded")
        try:
            if (oggi - datetime.date.fromisoformat(str(da)[:10])).days <= soglia_giorni:
                d["recenti"] += 1
        except (ValueError, TypeError):
            pass
    for d in agg.values():
        d["ratio"] = round(d["ransomware"] / d["kev"], 3) if d["kev"] else 0.0
    return agg


def classifica_ransomware(agg, top=15):
    """Vendor ordinati per numero assoluto di KEV armate dal ransomware."""
    return sorted(agg.items(), key=lambda kv: (kv[1]["ransomware"], kv[1]["kev"]),
                  reverse=True)[:top]


def classifica_tasso(agg, min_kev=MIN_KEV_RATIO, top=15):
    """Vendor ordinati per TASSO di weaponizzazione, escludendo i campioni troppo
    piccoli (dove un ratio alto sarebbe solo rumore statistico)."""
    grandi = [(vd, d) for vd, d in agg.items() if d["kev"] >= min_kev]
    return sorted(grandi, key=lambda kv: kv[1]["ratio"], reverse=True)[:top]


def classifica_recenti(agg, top=15):
    """Vendor con piu' KEV aggiunte nella finestra di trend, solo se > 0."""
    ordinati = sorted(agg.items(), key=lambda kv: kv[1]["recenti"], reverse=True)
    return [(vd, d) for vd, d in ordinati[:top] if d["recenti"] > 0]


def _tabella(righe, intestazione):
    out = ["| " + " | ".join(intestazione) + " |",
           "|" + "|".join([" --- "] * len(intestazione)) + "|"]
    for r in righe:
        out.append("| " + " | ".join(str(x) for x in r) + " |")
    return "\n".join(out)


def genera_report(agg, catalog_version="?", oggi=None, top=15) -> str:
    oggi = oggi or datetime.date.today()
    totale = sum(d["kev"] for d in agg.values())
    tot_ransom = sum(d["ransomware"] for d in agg.values())
    perc = int(round(tot_ransom / totale * 100)) if totale else 0

    t1 = _tabella(
        [(vd, d["kev"], d["ransomware"], f"{int(d['ratio'] * 100)}%", d["recenti"])
         for vd, d in classifica_ransomware(agg, top)],
        ["Vendor", "KEV", "Ransomware", "Tasso", f"Ultimi {MESI_TREND}m"])

    t2 = _tabella(
        [(vd, d["kev"], f"{int(d['ratio'] * 100)}%")
         for vd, d in classifica_tasso(agg, top=top)],
        ["Vendor", "KEV", "Tasso ransomware"])

    t3 = _tabella(
        [(vd, d["recenti"], d["kev"]) for vd, d in classifica_recenti(agg, top)],
        ["Vendor", f"Ultimi {MESI_TREND}m", "KEV totali"])

    return f"""**TLP:CLEAR**

# KEVlar - Vendor Risk Report ({oggi.strftime('%Y-%m')})

Fonte: **CISA KEV** (Known Exploited Vulnerabilities), catalogo {catalog_version}.
Vulnerabilita' sfruttate nel wild: **{totale}** (di cui armate dal ransomware:
**{tot_ransom}**, il {perc}%). Vendor distinti: {len(agg)}.

> **Come leggerlo.** Il numero di KEV da solo e' fuorviante: i prodotti ubiqui
> (Windows, Chrome, Linux) sono in cima perche' piu' usati e scrutinati, non
> perche' peggiori. Il segnale che orienta una scelta e' il **tasso di
> weaponizzazione** (quante falle sfruttate finiscono armate) e il **trend
> recente**. Un tasso alto con campione ampio = tipicamente edge/appliance
> (VPN, firewall, gateway, NAS): la porta d'ingresso preferita.

## 1. Weaponizzazione ransomware (segnale principale)
Vendor le cui KEV sfruttate finiscono piu' spesso in campagne ransomware.

{t1}

## 2. Tasso di weaponizzazione (campione >= {MIN_KEV_RATIO} KEV)
Il cluster "pensaci due volte / patcha aggressivo" - spesso edge/appliance.

{t2}

## 3. Trend: KEV aggiunte negli ultimi {MESI_TREND} mesi
Chi "scotta" ora.

{t3}

---

## Note e limiti
- Dati dal catalogo **pubblico** CISA KEV: una fotografia alla data del catalogo,
  che cambia a ogni aggiornamento.
- Il tasso di weaponizzazione e' **una lente** per prioritizzare patch e perimetro,
  **non** un giudizio sulla qualita' o sicurezza complessiva di un prodotto o di
  un'azienda. Un vendor molto diffuso e analizzato puo' avere numeri alti proprio
  per questo.
- La classificazione "ransomware" e' quella pubblicata da CISA (campo
  knownRansomwareCampaignUse), non un'attribuzione dell'autore.
- I nomi dei vendor sono citati a fini informativi/descrittivi, per riferirsi ai
  rispettivi prodotti. Nessuna affiliazione o endorsement e' implicata; i marchi
  appartengono ai rispettivi titolari.

*Generato da KEVlar (kevlar.py) su dato pubblico CISA KEV.*

**TLP:CLEAR** - This document may be distributed without restriction.
"""


def _esc(s):
    """Escape HTML dei nomi vendor (dato esterno da CISA). Copre anche apici e
    virgolette: cosi' e' sicuro anche se un valore finisce in un attributo (es.
    il filtro client-side del giorno 4), non solo nel testo."""
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&#39;"))


def _tabella_html(righe, intestazione):
    th = "".join(f"<th>{_esc(h)}</th>" for h in intestazione)
    corpo = "\n".join(
        "<tr>" + "".join(f"<td>{_esc(x)}</td>" for x in r) + "</tr>" for r in righe)
    return (f'<div class="tw"><table>\n<thead><tr>{th}</tr></thead>\n'
            f'<tbody>\n{corpo}\n</tbody></table></div>')


# CSS in costante a parte: stringa normale (parentesi letterali, niente doubling
# nelle f-string). Token su :root + override dark via prefers-color-scheme.
_HTML_CSS = """
:root { --bg:#f7f8fa; --fg:#1b1f24; --muted:#5a6572; --card:#fff; --bordo:#e2e6eb;
  --accent:#b4232a; --accent-soft:#fbeaea; --th:#eef1f4; }
@media (prefers-color-scheme: dark) { :root { --bg:#0f1216; --fg:#e6e9ed;
  --muted:#9aa4b0; --card:#161a20; --bordo:#2a3139; --accent:#ff6b72;
  --accent-soft:#2a1618; --th:#1c2128; } }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--fg);
  font:16px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }
.wrap { max-width:920px; margin:0 auto; padding:32px 16px 64px; }
.tlp { font:700 12px/1 system-ui; letter-spacing:.08em; color:var(--muted); }
h1 { font-size:1.9rem; margin:.2em 0 .1em; }
h2 { font-size:1.25rem; margin:2em 0 .2em; border-bottom:2px solid var(--bordo);
  padding-bottom:.25em; }
.sotto { color:var(--muted); margin:0 0 1em; }
.stat { display:flex; flex-wrap:wrap; gap:10px; margin:18px 0; }
.stat div { background:var(--card); border:1px solid var(--bordo); border-radius:10px;
  padding:10px 14px; }
.stat b { font-size:1.4rem; display:block; }
.callout { background:var(--accent-soft); border-left:4px solid var(--accent);
  border-radius:8px; padding:12px 16px; margin:18px 0; }
.tw { overflow-x:auto; }
table { border-collapse:collapse; width:100%; background:var(--card);
  border:1px solid var(--bordo); border-radius:10px; margin:8px 0 4px; font-size:.95rem; }
th,td { text-align:left; padding:9px 12px; border-bottom:1px solid var(--bordo); }
th { background:var(--th); font-weight:600; }
td:not(:first-child),th:not(:first-child) { text-align:right; white-space:nowrap; }
tbody tr:last-child td { border-bottom:0; }
.note { color:var(--muted); font-size:.9rem; }
footer { margin-top:2.5em; color:var(--muted); font-size:.85rem;
  border-top:1px solid var(--bordo); padding-top:1em; }
a { color:var(--accent); }
"""


def genera_html(agg, catalog_version="?", oggi=None, top=15) -> str:
    """Pagina HTML self-contained (stessi dati di genera_report). Niente build,
    niente dipendenze: pronta per GitHub Pages."""
    oggi = oggi or datetime.date.today()
    totale = sum(d["kev"] for d in agg.values())
    tot_ransom = sum(d["ransomware"] for d in agg.values())
    perc = int(round(tot_ransom / totale * 100)) if totale else 0

    t1 = _tabella_html(
        [(vd, d["kev"], d["ransomware"], f"{int(d['ratio'] * 100)}%", d["recenti"])
         for vd, d in classifica_ransomware(agg, top)],
        ["Vendor", "KEV", "Ransomware", "Tasso", f"Ultimi {MESI_TREND}m"])
    t2 = _tabella_html(
        [(vd, d["kev"], f"{int(d['ratio'] * 100)}%")
         for vd, d in classifica_tasso(agg, top=top)],
        ["Vendor", "KEV", "Tasso ransomware"])
    t3 = _tabella_html(
        [(vd, d["recenti"], d["kev"]) for vd, d in classifica_recenti(agg, top)],
        ["Vendor", f"Ultimi {MESI_TREND}m", "KEV totali"])

    return f"""<!doctype html>
<html lang="it">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>KEVlar - Vendor Risk</title>
<meta name="description" content="Rischio per vendor pesato sul ransomware, dal catalogo pubblico CISA KEV. TLP:CLEAR.">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<style>{_HTML_CSS}</style>
</head>
<body>
<div class="wrap">
<div class="tlp">TLP:CLEAR</div>
<h1>KEVlar &mdash; Vendor Risk</h1>
<p class="sotto">Rischio per vendor pesato sul ransomware, dal catalogo pubblico
<strong>CISA KEV</strong>. Catalogo {_esc(catalog_version)} &middot; {oggi.strftime('%Y-%m-%d')}.</p>

<div class="stat">
  <div><b>{totale}</b>vulnerabilita' sfruttate (KEV)</div>
  <div><b>{tot_ransom}</b>armate dal ransomware ({perc}%)</div>
  <div><b>{len(agg)}</b>vendor distinti</div>
</div>

<div class="callout">
<strong>Come leggerlo.</strong> Il numero di KEV da solo e' fuorviante: i prodotti
ubiqui (Windows, Chrome, Linux) sono in cima perche' piu' usati e scrutinati, non
perche' peggiori. Il segnale che orienta una scelta e' il <strong>tasso di
weaponizzazione</strong> (quante falle sfruttate finiscono armate) e il
<strong>trend recente</strong>. Un tasso alto con campione ampio = tipicamente
edge/appliance (VPN, firewall, gateway, NAS): la porta d'ingresso preferita.
</div>

<h2>1. Weaponizzazione ransomware (segnale principale)</h2>
<p class="sotto">Vendor le cui KEV sfruttate finiscono piu' spesso in campagne ransomware.</p>
{t1}

<h2>2. Tasso di weaponizzazione (campione &ge; {MIN_KEV_RATIO} KEV)</h2>
<p class="sotto">Il cluster "pensaci due volte / patcha aggressivo" &mdash; spesso edge/appliance.</p>
{t2}

<h2>3. Trend: KEV aggiunte negli ultimi {MESI_TREND} mesi</h2>
<p class="sotto">Chi "scotta" ora.</p>
{t3}

<footer>
<p class="note">Dati dal catalogo <strong>pubblico</strong> CISA KEV: una fotografia
alla data del catalogo. Il tasso di weaponizzazione e' <strong>una lente</strong> per
prioritizzare patch e perimetro, <strong>non</strong> un giudizio sulla qualita'
complessiva di un prodotto o di un'azienda. La classificazione "ransomware" e' quella
pubblicata da CISA (knownRansomwareCampaignUse), non un'attribuzione dell'autore. I
marchi appartengono ai rispettivi titolari; nessuna affiliazione e' implicata.</p>
<p>Generato da <strong>KEVlar</strong> su dato pubblico CISA KEV &middot;
<a href="https://github.com/aetheria-research/kevlar">github.com/aetheria-research/kevlar</a>
&middot; Autore: Manuel Carletti.</p>
<div class="tlp">TLP:CLEAR</div>
</footer>
</div>
</body>
</html>
"""


def snapshot(agg, catalog_version="?", oggi=None) -> dict:
    """Forma serializzabile (JSON) con tutti i vendor e i metadati del catalogo."""
    oggi = oggi or datetime.date.today()
    vendor = [{"vendor": vd, "kev": d["kev"], "ransomware": d["ransomware"],
               "ratio": d["ratio"], "recenti": d["recenti"]}
              for vd, d in agg.items()]
    return {
        "generato": oggi.isoformat(),
        "catalog_version": catalog_version,
        "totale_kev": sum(d["kev"] for d in agg.values()),
        "tot_ransomware": sum(d["ransomware"] for d in agg.values()),
        "mesi_trend": MESI_TREND,
        "min_kev_ratio": MIN_KEV_RATIO,
        "vendor": vendor,
    }


def scrivi_report(path_kev, output_dir=OUTPUT_DIR, oggi=None, html_path=None):
    """Scrive report .md + snapshot .json + pagina HTML. html_path sovrascrive il
    percorso HTML (default: <output_dir>/index.html, comodo per GitHub Pages)."""
    oggi = oggi or datetime.date.today()
    vulns, ver = carica_kev(path_kev)
    agg = aggrega_vendor(vulns, oggi=oggi)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    out = output_dir / f"vendor_risk_{oggi.strftime('%Y-%m')}.md"
    out.write_text(genera_report(agg, catalog_version=ver, oggi=oggi), encoding="utf-8")
    (output_dir / "vendor_risk_latest.json").write_text(
        json.dumps(snapshot(agg, ver, oggi), ensure_ascii=False, indent=2),
        encoding="utf-8")
    html_out = Path(html_path) if html_path else (output_dir / "index.html")
    html_out.parent.mkdir(parents=True, exist_ok=True)
    html_out.write_text(genera_html(agg, catalog_version=ver, oggi=oggi), encoding="utf-8")
    return out


def main():
    ap = argparse.ArgumentParser(description="KEVlar - vendor risk da CISA KEV.")
    ap.add_argument("--file", help="usa un catalogo KEV locale invece di scaricarlo")
    ap.add_argument("--out", default=str(OUTPUT_DIR), help="cartella di output")
    ap.add_argument("--html", help="percorso del file HTML (default: <out>/index.html)")
    ap.add_argument("--no-download", action="store_true",
                    help="non scaricare: usa la cache locale se presente")
    args = ap.parse_args()

    if args.file:
        kev_path = Path(args.file)
    elif args.no_download and CACHE_PATH.exists():
        kev_path = CACHE_PATH
    else:
        print("Scarico il catalogo CISA KEV (dato pubblico)...")
        kev_path = scarica_kev()

    out = scrivi_report(kev_path, args.out, html_path=args.html)
    html_out = Path(args.html) if args.html else Path(args.out) / "index.html"
    print(f"  report:   {out}")
    print(f"  snapshot: {Path(args.out) / 'vendor_risk_latest.json'}")
    print(f"  html:     {html_out}")


if __name__ == "__main__":
    main()
