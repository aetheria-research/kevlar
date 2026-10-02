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


def scrivi_report(path_kev, output_dir=OUTPUT_DIR, oggi=None):
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
    return out


def main():
    ap = argparse.ArgumentParser(description="KEVlar - vendor risk da CISA KEV.")
    ap.add_argument("--file", help="usa un catalogo KEV locale invece di scaricarlo")
    ap.add_argument("--out", default=str(OUTPUT_DIR), help="cartella di output")
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

    out = scrivi_report(kev_path, args.out)
    print(f"  report:   {out}")
    print(f"  snapshot: {Path(args.out) / 'vendor_risk_latest.json'}")


if __name__ == "__main__":
    main()
