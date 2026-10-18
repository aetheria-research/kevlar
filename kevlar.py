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
import base64
import collections
import datetime
import hashlib
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
    ratio ransomware/kev, prodotti (KEV e ransomware per prodotto). Ritorna
    {vendor: {...}}."""
    oggi = oggi or datetime.date.today()
    soglia_giorni = mesi_trend * 30
    agg = {}
    for v in vulns:
        vd = _campo(v, "vendorProject", "vendor") or "?"
        d = agg.setdefault(vd, {"kev": 0, "ransomware": 0, "recenti": 0,
                                "prodotti": collections.Counter(),
                                "prodotti_ransomware": collections.Counter()})
        # Nome prodotto come lo scrive CISA, solo con gli spazi ripuliti (ce ne
        # sono di iniziali/doppi). Nessuna unificazione delle varianti: sarebbe
        # un'interpretazione, non il dato.
        prodotto = " ".join(str(_campo(v, "product")).split()) or "?"
        d["kev"] += 1
        d["prodotti"][prodotto] += 1
        if str(_campo(v, "knownRansomwareCampaignUse")).lower() == "known":
            d["ransomware"] += 1
            d["prodotti_ransomware"][prodotto] += 1
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


def _pct(d):
    """Tasso ransomware in percentuale intera, arrotondato (mezzo in su) dai
    conteggi interi. UNICO arrotondamento per tabelle, grafico, filtro e --stack:
    prima le tabelle troncavano (9/11 -> 81%) e il grafico arrotondava (82%)."""
    return (200 * d["ransomware"] + d["kev"]) // (2 * d["kev"]) if d["kev"] else 0


def _nota_prodotto(d):
    """'tutte su X' / "per lo piu' X" se un prodotto domina le KEV del vendor,
    altrimenti ''. Cosi' "JetBrains 100%" si legge "tutte su TeamCity"."""
    if not d.get("prodotti"):
        return ""
    pn, pc = d["prodotti"].most_common(1)[0]
    if pc == d["kev"]:
        return f"tutte su {pn}"
    if pc >= d["kev"] * 0.6:
        return f"per lo piu' {pn}"
    return ""


def _prodotti_vendor(d, top=10):
    """Prodotti del vendor per numero di KEV (a parita', per ransomware):
    ([(prodotto, kev, ransomware), ...] i primi `top`, resto) dove resto e'
    (n_prodotti, kev, ransomware) di quelli oltre il taglio, o None."""
    rw = d.get("prodotti_ransomware", {})
    righe = sorted(((p, n, rw.get(p, 0)) for p, n in d.get("prodotti", {}).items()),
                   key=lambda r: (-r[1], -r[2], r[0]))
    oltre = righe[top:]
    resto = (len(oltre), sum(r[1] for r in oltre), sum(r[2] for r in oltre)) if oltre else None
    return righe[:top], resto


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
        [(vd, d["kev"], d["ransomware"], f"{_pct(d)}%", d["recenti"])
         for vd, d in classifica_ransomware(agg, top)],
        ["Vendor", "KEV", "Ransomware", "Tasso", f"Ultimi {MESI_TREND}m"])

    t2 = _tabella(
        [(vd, d["kev"], f"{_pct(d)}%")
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


def _grafico_tasso_svg(agg, top=12, min_kev=MIN_KEV_RATIO):
    """Barre orizzontali del TASSO di weaponizzazione per vendor. Serie singola
    -> un solo colore, nessuna legenda, etichette dirette, asse da 0 a 100%
    (onesto). SVG inline, nessun JS: tooltip via <title>, la tabella sotto fa da
    'table view'. Colori via classi CSS -> si adattano al tema chiaro/scuro."""
    righe = classifica_tasso(agg, min_kev=min_kev, top=top)
    if not righe:
        return ""
    barH, gap, top_m, bot_m = 22, 10, 34, 14
    x_lab, x0, x1, W = 184, 196, 620, 680
    H = top_m + len(righe) * (barH + gap) - gap + bot_m
    p = [f'<svg viewBox="0 0 {W} {H}" width="100%" role="img" '
         f'aria-label="Tasso di weaponizzazione ransomware per vendor" '
         f'class="kev-chart">']
    for tick in (0, 25, 50, 75, 100):  # asse da 0: lunghezza proporzionale al tasso
        gx = x0 + (x1 - x0) * tick / 100
        p.append(f'<line class="kev-grid" x1="{gx:.1f}" y1="{top_m - 6}" '
                 f'x2="{gx:.1f}" y2="{H - bot_m}"/>')
        p.append(f'<text class="kev-ax" x="{gx:.1f}" y="{top_m - 10}" '
                 f'text-anchor="middle">{tick}%</text>')
    y = top_m
    for vd, d in righe:
        bw = max((x1 - x0) * d["ratio"], 2)
        pct = _pct(d)
        cy = y + barH / 2 + 4
        p.append(f'<g><title>{_esc(vd)}: {pct}% ({d["ransomware"]}/{d["kev"]} KEV)</title>'
                 f'<text class="kev-lab" x="{x_lab}" y="{cy:.1f}" text-anchor="end">'
                 f'{_esc(vd[:22])}</text>'
                 f'<rect class="kev-bar" x="{x0}" y="{y}" width="{bw:.1f}" '
                 f'height="{barH}" rx="4"/>'
                 f'<text class="kev-val" x="{x0 + bw + 6:.1f}" y="{cy:.1f}">{pct}%</text></g>')
        y += barH + gap
    p.append('</svg>')
    return f'<figure class="kev-fig">{"".join(p)}</figure>'


def _dettaglio_prodotti_html(agg, top=15, top_prodotti=10):
    """Un <details> per ogni vendor delle classifiche (per ransomware e per
    tasso): dentro, i suoi prodotti con KEV e ransomware. Elemento HTML nativo,
    si apre al clic senza JS -> la CSP resta com'e'. Per prodotto solo conteggi,
    niente percentuali: su 1-4 KEV un tasso sarebbe rumore."""
    scelti = dict(classifica_ransomware(agg, top))
    scelti.update(classifica_tasso(agg, top=top))
    ordinati = sorted(scelti.items(), key=lambda kv: (kv[1]["ransomware"], kv[1]["kev"]),
                      reverse=True)
    blocchi = []
    for vd, d in ordinati:
        righe, resto = _prodotti_vendor(d, top_prodotti)
        if resto:
            righe = righe + [(f"altri {resto[0]} prodotti", resto[1], resto[2])]
        meta = [f"{d['kev']} KEV", f"{_pct(d)}% ransomware",
                _nota_prodotto(d) or f"{len(d.get('prodotti', {}))} prodotti"]
        if d["kev"] < MIN_KEV_RATIO:
            meta.append("campione piccolo")
        tabella = _tabella_html(righe, ["Prodotto (nome CISA)", "KEV", "Ransomware"])
        blocchi.append(f'<details class="kp"><summary><strong>{_esc(vd)}</strong> '
                       f'<span class="kp-meta">{" &middot; ".join(_esc(m) for m in meta)}'
                       f'</span></summary>\n{tabella}\n</details>')
    return "\n".join(blocchi)


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
.kev-fig { margin:12px 0 4px; overflow-x:auto; }
.kev-chart { max-width:680px; }
.kev-chart text { font:12px system-ui,-apple-system,sans-serif; }
.kev-grid { stroke:var(--bordo); stroke-width:1; }
.kev-ax { fill:var(--muted); }
.kev-lab { fill:var(--fg); }
.kev-val { fill:var(--fg); font-weight:600; }
.kev-bar { fill:var(--accent); }
#kv-in { width:100%; max-width:420px; padding:8px 10px; border:1px solid var(--bordo);
  border-radius:8px; background:var(--card); color:var(--fg);
  font:15px system-ui,-apple-system,sans-serif; }
.kv-out { margin:10px 0 2px; font-size:.95rem; }
.kv-out ul { margin:6px 0; padding-left:20px; }
.kv-out li { margin:2px 0; }
details.kp { background:var(--card); border:1px solid var(--bordo); border-radius:10px;
  margin:8px 0; }
details.kp > summary { cursor:pointer; padding:10px 14px; }
details.kp[open] > summary { border-bottom:1px solid var(--bordo); }
.kp-meta { color:var(--muted); font-size:.92rem; }
details.kp .tw { padding:4px 8px 8px; }
details.kp table { border:0; margin:0; }
"""


# Logica del riquadro "Ti riguarda?" (corpo, senza i dati). Gira dopo "var K=...".
# Solo textContent / createElement sull'input utente: nessun innerHTML, nessun
# eval -> niente injection. Lo script e' permesso in CSP solo tramite il suo hash
# sha256 (calcolato alla generazione in genera_html), non con 'unsafe-inline'.
_JS_FILTRO_BODY = (
    "var b=document.getElementById('kv-in'),o=document.getElementById('kv-out');"
    "if(!b)return;"
    "function upd(){"
    "var ts=b.value.slice(0,2000).split(/[,\\n]/).map(function(s){"
    "return s.trim().toLowerCase().replace(/[^a-z0-9 ._\\/-]/g,'').slice(0,64);"
    "}).filter(Boolean).slice(0,50);"
    "o.textContent='';"
    "if(!ts.length){o.textContent='Incolla i tuoi vendor per sapere quali compaiono nel catalogo CISA KEV.';return;}"
    "var tr=[],ab=[],rt=0;"
    "ts.forEach(function(t){var h=null;for(var i=0;i<K.length;i++){var dl=K[i][0].toLowerCase();"
    "if(dl.indexOf(t)>-1||t.indexOf(dl)>-1){if(!h||K[i][2]>h[2])h=K[i];}}"
    "if(h){tr.push(h);rt+=h[2];}else{ab.push(t);}});"
    "var avg=tr.length?Math.round(rt/tr.length):0;"
    "var p=document.createElement('p');p.textContent='Dei '+ts.length+' inseriti: '+tr.length"
    "+' nel catalogo CISA KEV'+(tr.length?' (tasso ransomware medio '+avg+'%)':'')+'.';o.appendChild(p);"
    "if(tr.length){var u=document.createElement('ul');tr.forEach(function(x){var li=document.createElement('li');"
    "li.textContent=x[0]+' \\u2014 '+x[1]+' KEV, tasso '+x[2]+'%'+(x[1]<10?' (campione piccolo)':'');"
    "u.appendChild(li);});o.appendChild(u);}"
    "if(ab.length){var q=document.createElement('p');q.textContent='Non nel KEV (nessun red flag): '"
    "+ab.join(', ')+'.';o.appendChild(q);}"
    "}"
    "b.addEventListener('input',upd);upd();"
)


def genera_html(agg, catalog_version="?", oggi=None, top=15) -> str:
    """Pagina HTML self-contained (stessi dati di genera_report). Niente build,
    niente dipendenze: pronta per GitHub Pages."""
    oggi = oggi or datetime.date.today()
    totale = sum(d["kev"] for d in agg.values())
    tot_ransom = sum(d["ransomware"] for d in agg.values())
    perc = int(round(tot_ransom / totale * 100)) if totale else 0

    t1 = _tabella_html(
        [(vd, d["kev"], d["ransomware"], f"{_pct(d)}%", d["recenti"])
         for vd, d in classifica_ransomware(agg, top)],
        ["Vendor", "KEV", "Ransomware", "Tasso", f"Ultimi {MESI_TREND}m"])
    t2 = _tabella_html(
        [(vd, d["kev"], f"{_pct(d)}%")
         for vd, d in classifica_tasso(agg, top=top)],
        ["Vendor", "KEV", "Tasso ransomware"])
    t3 = _tabella_html(
        [(vd, d["recenti"], d["kev"]) for vd, d in classifica_recenti(agg, top)],
        ["Vendor", f"Ultimi {MESI_TREND}m", "KEV totali"])
    grafico = _grafico_tasso_svg(agg, top)
    prodotti = _dettaglio_prodotti_html(agg, top)
    sezione_prodotti = f"""
<h2 id="prodotti">4. Dentro i vendor: quali prodotti</h2>
<p class="sotto">Apri un vendor per vedere su quali prodotti cadono le sue KEV. Un tasso alto
concentrato su un solo prodotto e' un "verifica QUEL prodotto, se lo esponi", non un
giudizio sul vendor.</p>
{prodotti}
<p class="note">Nomi dei prodotti come li scrive CISA: lo stesso prodotto puo' comparire con
varianti (es. "Confluence Server" e "Confluence Data Center and Server"). Per prodotto
solo i conteggi, non un tasso: su poche falle una percentuale sarebbe rumore.</p>
""" if prodotti else ""
    link_prodotti = '<a href="#prodotti">Su quali prodotti?</a>' if prodotti else ""

    # Riquadro "Ti riguarda?": tutti i vendor (non solo i top) finiscono in un
    # array JS, cosi' il filtro risponde per qualunque vendor l'utente digiti,
    # anche quelli assenti dal KEV. Lo script e' permesso in CSP SOLO col suo
    # hash sha256, calcolato qui sul testo esatto (dati inclusi): se cambia, si
    # ricalcola da solo. Niente 'unsafe-inline' per gli script.
    kev_lista = [[vd, d["kev"], _pct(d)]
                 for vd, d in sorted(agg.items(), key=lambda kv: -kv[1]["kev"])]
    script = ("(function(){var K=" + json.dumps(kev_lista, ensure_ascii=False)
              + ";" + _JS_FILTRO_BODY + "})();")
    # Se un nome vendor contenesse "</script>" chiuderebbe il tag in anticipo:
    # "<\/" e' equivalente in JS e innocuo nell'HTML. L'hash si calcola DOPO,
    # sul testo esatto che finisce nella pagina.
    script = script.replace("</", "<\\/")
    sha = base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode()
    csp = ("default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-"
           + sha + "'; object-src 'none'; base-uri 'none'; form-action 'none'")

    return f"""<!doctype html>
<html lang="it">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>KEVlar - Vendor Risk</title>
<meta name="description" content="Rischio per vendor pesato sul ransomware, dal catalogo pubblico CISA KEV. TLP:CLEAR.">
<meta http-equiv="Content-Security-Policy" content="{csp}">
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

<h2>Ti riguarda?</h2>
<p class="sotto">Incolla i tuoi vendor/tecnologie: ti dico quali compaiono nel CISA KEV
e il tasso ransomware medio del tuo stack.</p>
<input id="kv-in" type="text" maxlength="2000" placeholder="Fortinet, Microsoft, VMware"
 autocomplete="off" spellcheck="false" aria-label="I tuoi vendor, separati da virgola">
<div id="kv-out" class="kv-out"></div>
<p class="note">Assenza dal KEV = nessuna vulnerabilita' sfruttata NOTA e tracciata da
CISA: e' un buon segno, non una prova di sicurezza.</p>

<h2>1. Weaponizzazione ransomware (segnale principale)</h2>
<p class="sotto">Vendor le cui KEV sfruttate finiscono piu' spesso in campagne ransomware.
{link_prodotti}</p>
{t1}

<h2>2. Tasso di weaponizzazione (campione &ge; {MIN_KEV_RATIO} KEV)</h2>
<p class="sotto">Il cluster "pensaci due volte / patcha aggressivo" &mdash; spesso edge/appliance.</p>
{grafico}
{t2}

<h2>3. Trend: KEV aggiunte negli ultimi {MESI_TREND} mesi</h2>
<p class="sotto">Chi "scotta" ora.</p>
{t3}
{sezione_prodotti}
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
<script>{script}</script>
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


def valuta_stack(agg, vendors):
    """Dato lo stack dell'utente (lista di vendor), ritorna quali compaiono nel
    KEV (con kev/ransomware/tasso) e quali no. Match 'morbido' (nome parziale),
    coerente col filtro 'ti riguarda?' della pagina: un termine aggancia il
    vendor col tasso piu' alto fra quelli che combaciano. Niente da inventare:
    chi non c'e' finisce in 'assenti' (nessun red flag, non prova di sicurezza)."""
    coppie = [(vd.lower(), vd, d) for vd, d in agg.items()]
    trovati, assenti, somma = [], [], 0.0
    for raw in vendors:
        t = raw.strip()
        tl = t.lower()
        if not tl:
            continue
        best = None
        for vdl, vd, d in coppie:
            if vdl in tl or tl in vdl:
                if best is None or d["ratio"] > best[2]["ratio"]:
                    best = (vdl, vd, d)
        if best:
            trovati.append((t, best[1], best[2]))
            somma += best[2]["ratio"]
        else:
            assenti.append(t)
    tasso = round(somma / len(trovati), 3) if trovati else 0.0
    return {"trovati": trovati, "assenti": assenti, "tasso_medio": tasso}


def report_stack(ris) -> str:
    """Rende leggibile il risultato di valuta_stack (per il terminale). Onesto
    sul campione: un tasso su poche KEV (es. 4/4 = 100%) e' segnalato come poco
    significativo - la stessa cautela del filtro >=10 della classifica. E mostra
    il prodotto dominante, cosi' "JetBrains 100%" si legge "tutte su TeamCity"."""
    n = len(ris["trovati"]) + len(ris["assenti"])
    out = [f"Il tuo stack: {len(ris['trovati'])}/{n} vendor nel CISA KEV "
           f"(tasso ransomware medio {int(round(ris['tasso_medio'] * 100))}%)."]
    piccoli = 0
    for _, vd, d in sorted(ris["trovati"], key=lambda x: -x[2]["ratio"]):
        dominante = _nota_prodotto(d)
        pezzo = f" - {dominante}" if dominante else ""
        nota = ""
        if d["kev"] < MIN_KEV_RATIO:
            piccoli += 1
            nota = f"  [campione piccolo: {d['kev']} KEV, tasso poco significativo]"
        out.append(f"  [{_pct(d):>3}%] {vd}{pezzo}  "
                   f"({d['ransomware']}/{d['kev']} KEV armate){nota}")
    if piccoli:
        out.append(f"  Nota: {piccoli} con meno di {MIN_KEV_RATIO} KEV. Un tasso su "
                   f"pochi casi (es. 4/4 = 100%) non e' un giudizio robusto sul vendor: "
                   f"e' un 'verifica QUEL prodotto, se lo esponi'.")
    if ris["assenti"]:
        out.append(f"  Non nel KEV (nessun red flag): {', '.join(ris['assenti'])}")
    return "\n".join(out)


def _leggi_stack(valore):
    """--stack accetta un file (un vendor per riga o separati da virgola) oppure
    direttamente una lista separata da virgola."""
    import re as _re
    p = Path(valore)
    testo = p.read_text(encoding="utf-8") if p.is_file() else valore
    return [s for s in _re.split(r"[,\n]", testo) if s.strip()]


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
    ap.add_argument("--stack", help="i TUOI vendor (lista separata da virgola o file): "
                    "stampa quali sono nel KEV e il tasso, senza generare il report")
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

    # Modalita' --stack: query focalizzata sul tuo parco tecnologico, niente
    # file di output (e' una consultazione, non una pubblicazione).
    if args.stack:
        vulns, ver = carica_kev(kev_path)
        agg = aggrega_vendor(vulns)
        print(report_stack(valuta_stack(agg, _leggi_stack(args.stack))))
        return

    out = scrivi_report(kev_path, args.out, html_path=args.html)
    html_out = Path(args.html) if args.html else Path(args.out) / "index.html"
    print(f"  report:   {out}")
    print(f"  snapshot: {Path(args.out) / 'vendor_risk_latest.json'}")
    print(f"  html:     {html_out}")


if __name__ == "__main__":
    main()
