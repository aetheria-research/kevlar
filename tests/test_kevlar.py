"""Test per kevlar.py - esegui con:  python -m pytest tests/ -q"""
import datetime
import json

import kevlar as kv

OGGI = datetime.date(2026, 9, 28)


def _kev(vendor, product="p", ransomware=False, dateAdded="2026-09-01"):
    return {
        "vendorProject": vendor,
        "product": product,
        "knownRansomwareCampaignUse": "Known" if ransomware else "Unknown",
        "dateAdded": dateAdded,
    }


def test_aggrega_conta_kev_e_ransomware():
    vulns = [_kev("QNAP", ransomware=True), _kev("QNAP", ransomware=False)]
    agg = kv.aggrega_vendor(vulns, oggi=OGGI)
    assert agg["QNAP"]["kev"] == 2
    assert agg["QNAP"]["ransomware"] == 1


def test_ratio_calcolato():
    vulns = [_kev("X", ransomware=True), _kev("X", ransomware=True),
             _kev("X", ransomware=False), _kev("X", ransomware=False)]
    agg = kv.aggrega_vendor(vulns, oggi=OGGI)
    assert agg["X"]["ratio"] == 0.5


def test_recenti_rispetta_la_finestra():
    vulns = [_kev("X", dateAdded="2026-09-01"),   # dentro la finestra
             _kev("X", dateAdded="2019-01-01")]   # fuori (oltre 12 mesi)
    agg = kv.aggrega_vendor(vulns, oggi=OGGI)
    assert agg["X"]["recenti"] == 1


def test_dateadded_malformata_non_rompe():
    vulns = [_kev("X", dateAdded="non-una-data"), _kev("X", dateAdded="")]
    agg = kv.aggrega_vendor(vulns, oggi=OGGI)
    assert agg["X"]["kev"] == 2
    assert agg["X"]["recenti"] == 0


def test_classifica_tasso_filtra_campioni_piccoli():
    # SmallCo: 2 KEV entrambe ransomware (100%) ma sotto soglia -> escluso
    # BigCo: 12 KEV, 3 ransomware (25%) -> incluso
    vulns = [_kev("SmallCo", ransomware=True), _kev("SmallCo", ransomware=True)]
    vulns += [_kev("BigCo", ransomware=(i < 3)) for i in range(12)]
    agg = kv.aggrega_vendor(vulns, oggi=OGGI)
    nomi = [vd for vd, _ in kv.classifica_tasso(agg, min_kev=10)]
    assert "BigCo" in nomi
    assert "SmallCo" not in nomi


def test_classifica_ransomware_ordina_per_conteggio():
    vulns = [_kev("A", ransomware=True)]
    vulns += [_kev("B", ransomware=True) for _ in range(3)]
    agg = kv.aggrega_vendor(vulns, oggi=OGGI)
    assert kv.classifica_ransomware(agg)[0][0] == "B"


def test_carica_kev_formato_dict(tmp_path):
    p = tmp_path / "kev.json"
    p.write_text(json.dumps({"catalogVersion": "2026.09",
                             "vulnerabilities": [_kev("X", ransomware=True)]}),
                 encoding="utf-8")
    vulns, ver = kv.carica_kev(p)
    assert ver == "2026.09"
    assert len(vulns) == 1


def test_carica_kev_formato_lista(tmp_path):
    p = tmp_path / "kev.json"
    p.write_text(json.dumps([_kev("X")]), encoding="utf-8")
    vulns, ver = kv.carica_kev(p)
    assert len(vulns) == 1
    assert ver == "?"


def test_carica_kev_file_mancante(tmp_path):
    vulns, ver = kv.carica_kev(tmp_path / "non_esiste.json")
    assert vulns == []
    assert ver == "?"


def test_genera_report_contiene_sezioni_e_disclaimer():
    vulns = [_kev("BigCo", ransomware=(i < 5)) for i in range(12)]
    agg = kv.aggrega_vendor(vulns, oggi=OGGI)
    testo = kv.genera_report(agg, catalog_version="2026.09", oggi=OGGI)
    assert "TLP:CLEAR" in testo
    assert "Tasso di weaponizzazione" in testo
    assert "Note e limiti" in testo
    assert "BigCo" in testo


def test_genera_html_struttura_e_disclaimer():
    vulns = [_kev("BigCo", ransomware=(i < 5)) for i in range(12)]
    agg = kv.aggrega_vendor(vulns, oggi=OGGI)
    html = kv.genera_html(agg, catalog_version="2026.09", oggi=OGGI)
    assert html.lstrip().startswith("<!doctype html>")
    assert "<table" in html and "</table>" in html
    assert "TLP:CLEAR" in html
    assert "Tasso di weaponizzazione" in html
    assert "BigCo" in html and "2026.09" in html


def test_genera_html_escape_nomi_vendor():
    # I nomi vendor vengono da dato esterno: vanno escapizzati, non iniettati.
    # Copre anche " e ' (sicurezza anche in contesto attributo).
    vulns = [_kev('A"<b>&x', ransomware=True) for _ in range(10)]
    agg = kv.aggrega_vendor(vulns, oggi=OGGI)
    html = kv.genera_html(agg, oggi=OGGI)
    assert 'A"<b>&x' not in html
    assert "A&quot;&lt;b&gt;&amp;x" in html


def test_grafico_tasso_svg_barre_e_valori():
    vulns = [_kev("EdgeCo", ransomware=(i < 8)) for i in range(10)]  # 80%
    agg = kv.aggrega_vendor(vulns, oggi=OGGI)
    svg = kv._grafico_tasso_svg(agg)
    assert svg.startswith("<figure") and "<svg" in svg
    assert "kev-bar" in svg and "EdgeCo" in svg and "80%" in svg
    assert "<script" not in svg.lower()  # niente JS: CSP resta chiusa


def test_pct_arrotonda_dai_conteggi():
    assert kv._pct({"kev": 11, "ransomware": 9}) == 82   # 81,8%: non troncato a 81
    assert kv._pct({"kev": 8, "ransomware": 1}) == 13    # 12,5%: mezzo in su
    assert kv._pct({"kev": 0, "ransomware": 0}) == 0     # niente divisione per zero


def test_stesso_tasso_in_tabelle_grafico_e_filtro():
    # 9/11 = 81,8%: prima le tabelle dicevano 81% e il grafico 82% sulla stessa
    # pagina. Ora tabelle, grafico, filtro e report Markdown dicono tutti 82%.
    vulns = [_kev("NasCo", ransomware=(i < 9)) for i in range(11)]
    agg = kv.aggrega_vendor(vulns, oggi=OGGI)
    html = kv.genera_html(agg, oggi=OGGI)
    assert "<td>82%</td>" in html            # tabelle
    assert "NasCo: 82%" in html              # grafico (tooltip)
    assert '["NasCo", 11, 82]' in html       # dati del filtro "ti riguarda?"
    assert "81%" not in html
    assert "| 82% |" in kv.genera_report(agg, oggi=OGGI)


def test_grafico_tasso_svg_vuoto_se_nessun_campione():
    # solo campioni sotto soglia -> nessuna barra, stringa vuota, pagina regge
    vulns = [_kev("SmallCo", ransomware=True) for _ in range(3)]
    agg = kv.aggrega_vendor(vulns, oggi=OGGI)
    assert kv._grafico_tasso_svg(agg) == ""


def test_genera_html_include_il_grafico():
    vulns = [_kev("EdgeCo", ransomware=(i < 6)) for i in range(10)]
    agg = kv.aggrega_vendor(vulns, oggi=OGGI)
    html = kv.genera_html(agg, oggi=OGGI)
    assert "kev-bar" in html and "<svg" in html


def test_genera_html_csp_script_solo_via_hash():
    # Pagina pubblica: CSP restrittiva; lo script del filtro e' permesso SOLO
    # tramite il suo hash sha256, mai con 'unsafe-inline'.
    vulns = [_kev("X", ransomware=True) for _ in range(10)]
    agg = kv.aggrega_vendor(vulns, oggi=OGGI)
    html = kv.genera_html(agg, oggi=OGGI)
    assert "Content-Security-Policy" in html and "default-src 'none'" in html
    assert "script-src 'sha256-" in html
    assert "script-src 'unsafe-inline'" not in html


def test_genera_html_csp_hash_combacia_con_lo_script():
    # Il browser esegue lo script SOLO se l'hash in CSP combacia col contenuto.
    import re
    import hashlib
    import base64
    vulns = [_kev("EdgeCo", ransomware=(i < 6)) for i in range(10)]
    agg = kv.aggrega_vendor(vulns, oggi=OGGI)
    html = kv.genera_html(agg, oggi=OGGI)
    m = re.search(r"<script>(.*?)</script>", html, re.S)
    assert m, "script del filtro assente"
    h = base64.b64encode(hashlib.sha256(m.group(1).encode("utf-8")).digest()).decode()
    assert ("sha256-" + h) in html, "l'hash CSP non combacia con lo script"


def test_genera_html_input_indurito():
    # Difesa in profondita' sull'input del filtro: lunghezza + numero termini +
    # allowlist dei caratteri; CSP senza plugin/embed.
    vulns = [_kev("X", ransomware=True) for _ in range(10)]
    agg = kv.aggrega_vendor(vulns, oggi=OGGI)
    html = kv.genera_html(agg, oggi=OGGI)
    assert 'maxlength="2000"' in html          # input limitato
    assert "object-src 'none'" in html          # niente plugin/embed
    assert ".slice(0,50)" in html               # cap sul numero di termini
    assert "replace(/[^a-z0-9" in html          # allowlist sui caratteri


def test_genera_html_filtro_ti_riguarda_presente_coi_dati():
    vulns = [_kev("EdgeCo", ransomware=(i < 6)) for i in range(10)]
    agg = kv.aggrega_vendor(vulns, oggi=OGGI)
    html = kv.genera_html(agg, oggi=OGGI)
    assert 'id="kv-in"' in html         # il riquadro
    assert "non una prova di sicurezza" in html  # il caveat onesto
    assert "EdgeCo" in html             # dati vendor nel filtro


def test_scrivi_report_emette_md_json_e_html(tmp_path):
    p = tmp_path / "kev.json"
    p.write_text(json.dumps({"catalogVersion": "2026.09",
                             "vulnerabilities": [_kev("X", ransomware=True)]}),
                 encoding="utf-8")
    out = kv.scrivi_report(p, output_dir=tmp_path / "o", oggi=OGGI)
    assert out.exists()                                        # .md
    assert (tmp_path / "o" / "vendor_risk_latest.json").exists()
    assert (tmp_path / "o" / "index.html").exists()            # NUOVO


def test_scrivi_report_rispetta_html_path(tmp_path):
    p = tmp_path / "kev.json"
    p.write_text(json.dumps([_kev("X")]), encoding="utf-8")
    html = tmp_path / "public" / "index.html"
    kv.scrivi_report(p, output_dir=tmp_path / "o", oggi=OGGI, html_path=str(html))
    assert html.exists()


def test_workflow_pages_igiene_sicurezza():
    """Guardia CI: il workflow Pages deve restare 'igienico' - permessi minimi,
    nessun trigger pericoloso, solo action ufficiali, build dal nostro script."""
    import pathlib
    import re
    root = pathlib.Path(__file__).resolve().parents[1]
    wf = (root / ".github" / "workflows" / "kevlar-live.yml").read_text(encoding="utf-8")
    assert "pull_request_target" not in wf        # il trigger pericoloso: MAI
    assert "contents: read" in wf                 # permessi minimi
    assert "workflow_dispatch" in wf and "schedule" in wf
    assert "python kevlar.py" in wf               # build dal nostro codice
    usi = re.findall(r"uses:\s*([^@\s]+)@", wf)
    assert usi, "nessuna action trovata"
    assert all(u.startswith("actions/") for u in usi), f"action non ufficiale: {usi}"


def test_valuta_stack_trova_e_separa():
    vulns = [_kev("Fortinet", ransomware=(i < 5)) for i in range(10)]   # 50%
    vulns += [_kev("QNAP", ransomware=True) for _ in range(4)]           # 100%
    agg = kv.aggrega_vendor(vulns, oggi=OGGI)
    r = kv.valuta_stack(agg, ["Fortinet", "QNAP", "Tailscale"])
    nomi = [t[1] for t in r["trovati"]]
    assert "Fortinet" in nomi and "QNAP" in nomi
    assert r["assenti"] == ["Tailscale"]          # non nel KEV -> assente, onesto
    assert 0.74 < r["tasso_medio"] < 0.76         # media di 50% e 100%


def test_valuta_stack_match_morbido():
    vulns = [_kev("Fortinet", ransomware=True) for _ in range(10)]
    agg = kv.aggrega_vendor(vulns, oggi=OGGI)
    r = kv.valuta_stack(agg, ["forti"])           # nome parziale
    assert len(r["trovati"]) == 1 and r["trovati"][0][1] == "Fortinet"


def test_report_stack_leggibile():
    vulns = [_kev("QNAP", ransomware=True) for _ in range(12)]
    agg = kv.aggrega_vendor(vulns, oggi=OGGI)
    testo = kv.report_stack(kv.valuta_stack(agg, ["QNAP", "Tailscale"]))
    assert "Il tuo stack" in testo and "QNAP" in testo
    assert "nessun red flag" in testo and "Tailscale" in testo


def test_report_stack_segnala_campione_piccolo_e_prodotto():
    # Caso JetBrains reale: 4 KEV, tutte TeamCity, tutte ransomware -> 100% ma
    # campione piccolo. Il report deve dirlo (onesta' statistica + prodotto).
    vulns = [_kev("JetBrains", product="TeamCity", ransomware=True) for _ in range(4)]
    agg = kv.aggrega_vendor(vulns, oggi=OGGI)
    testo = kv.report_stack(kv.valuta_stack(agg, ["JetBrains"]))
    assert "100%" in testo
    assert "campione piccolo" in testo        # cautela sul campione
    assert "TeamCity" in testo                # il prodotto vero, non "l'IDE"


def test_filtro_web_segnala_campione_piccolo():
    vulns = [_kev("SmallCo", ransomware=True) for _ in range(4)]  # <10 KEV
    agg = kv.aggrega_vendor(vulns, oggi=OGGI)
    html = kv.genera_html(agg, oggi=OGGI)
    assert "campione piccolo" in html


def test_leggi_stack_da_lista_e_da_file(tmp_path):
    assert kv._leggi_stack("Fortinet, QNAP") == ["Fortinet", " QNAP"]
    f = tmp_path / "stack.txt"
    f.write_text("Fortinet\nQNAP\nVMware\n", encoding="utf-8")
    assert kv._leggi_stack(str(f)) == ["Fortinet", "QNAP", "VMware"]


def test_snapshot_struttura():
    vulns = [_kev("X", ransomware=True)]
    agg = kv.aggrega_vendor(vulns, oggi=OGGI)
    snap = kv.snapshot(agg, "2026.09", oggi=OGGI)
    assert snap["totale_kev"] == 1
    assert snap["tot_ransomware"] == 1
    assert snap["catalog_version"] == "2026.09"
    assert snap["vendor"][0]["vendor"] == "X"
