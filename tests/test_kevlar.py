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


def test_carica_kev_formati_anomali_non_crashano(tmp_path):
    p = tmp_path / "kev.json"
    for contenuto in ['123', '"testo"', '{"vulnerabilities": "non-lista"}',
                      '<html>Service Unavailable</html>']:
        p.write_text(contenuto, encoding="utf-8")
        assert kv.carica_kev(p) == ([], "?"), contenuto
    p.write_bytes(b"\xff\xfe\x00 non utf-8")
    assert kv.carica_kev(p) == ([], "?")
    p.write_text(json.dumps([_kev("X"), "voce-non-dict", 7]), encoding="utf-8")
    vulns, _ = kv.carica_kev(p)
    assert len(vulns) == 1                       # tenute solo le voci dict


class _RispostaFinta:
    """Sostituto della connessione (kv._apri): niente rete nei test."""
    def __init__(self, dati, url=kv.CISA_KEV_URL):
        self.dati = dati
        self.url = url

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def geturl(self):
        return self.url

    def read(self, n=-1):
        return self.dati if n < 0 else self.dati[:n]


def _catalogo_bytes(n=1000):
    """Catalogo valido e plausibile (>= MIN_KEV_PLAUSIBILI voci), in bytes."""
    return json.dumps({"catalogVersion": "2026.10",
                       "vulnerabilities": [_kev("X") for _ in range(n)]}).encode("utf-8")


def _rifiuta(fn):
    try:
        fn()
    except ValueError:
        return True
    return False


def test_scarica_kev_risposta_anomala_non_tocca_la_cache(tmp_path, monkeypatch):
    cache = tmp_path / "cache.json"
    cache.write_text("CACHE BUONA", encoding="utf-8")
    monkeypatch.setattr(kv, "_apri",
                        lambda url, timeout: _RispostaFinta(b"<html>Errore 503</html>"))
    assert _rifiuta(lambda: kv.scarica_kev(cache=cache))
    assert cache.read_text(encoding="utf-8") == "CACHE BUONA"


def test_scarica_kev_risposta_troppo_grande(tmp_path, monkeypatch):
    monkeypatch.setattr(kv, "MAX_BYTES_CATALOGO", 10)
    monkeypatch.setattr(kv, "_apri", lambda url, timeout: _RispostaFinta(b"x" * 100))
    assert _rifiuta(lambda: kv.scarica_kev(cache=tmp_path / "cache.json"))
    assert not (tmp_path / "cache.json").exists()


def test_scarica_kev_risposta_valida_scrive_la_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(kv, "_apri", lambda url, timeout: _RispostaFinta(_catalogo_bytes()))
    cache = kv.scarica_kev(cache=tmp_path / "cache.json")
    assert kv.carica_kev(cache)[1] == "2026.10"


def test_scarica_kev_rifiuta_catalogo_implausibile(tmp_path, monkeypatch):
    # JSON valido ma con 5 voci: troncato o manipolato -> non diventa la dashboard
    monkeypatch.setattr(kv, "_apri", lambda url, timeout: _RispostaFinta(_catalogo_bytes(5)))
    assert _rifiuta(lambda: kv.scarica_kev(cache=tmp_path / "cache.json"))
    assert not (tmp_path / "cache.json").exists()


def test_scarica_kev_rifiuta_url_finale_fuori_da_cisa(tmp_path, monkeypatch):
    # dati perfetti, ma arrivati (dopo un redirect) da un host diverso da cisa.gov
    monkeypatch.setattr(kv, "_apri", lambda url, timeout: _RispostaFinta(
        _catalogo_bytes(), url="https://cisa.gov.evil.example/kev.json"))
    assert _rifiuta(lambda: kv.scarica_kev(cache=tmp_path / "cache.json"))
    assert not (tmp_path / "cache.json").exists()


def test_verifica_url_solo_https_su_cisa():
    kv._verifica_url(kv.CISA_KEV_URL)                              # la fonte vera
    kv._verifica_url("https://cisa.gov/feed.json")
    for cattivo in ["http://www.cisa.gov/feed.json",              # in chiaro
                    "https://evil.example/feed.json",              # altro host
                    "https://cisa.gov.evil.example/feed.json",     # suffisso finto
                    "https://evilcisa.gov/feed.json",              # dominio simile
                    "https://user@evil.example/www.cisa.gov",      # host nascosto
                    "ftp://www.cisa.gov/feed.json",
                    "file:///etc/passwd"]:
        assert _rifiuta(lambda: kv._verifica_url(cattivo)), cattivo


def test_redirect_verso_http_rifiutato():
    import urllib.request
    req = urllib.request.Request(kv.CISA_KEV_URL)
    gestore = kv._RedirectSicuro()
    assert _rifiuta(lambda: gestore.redirect_request(
        req, None, 302, "Found", {}, "http://www.cisa.gov/feed.json"))
    # un redirect lecito (https, stesso dominio) passa
    assert gestore.redirect_request(req, None, 302, "Found", {},
                                    "https://www.cisa.gov/altro.json") is not None


def test_apri_rifiuta_url_prima_di_toccare_la_rete():
    assert _rifiuta(lambda: kv._apri("http://www.cisa.gov/feed.json", timeout=1))


def test_contesto_tls_verificato_e_moderno():
    import ssl
    ctx = kv._contesto_tls()
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_testo_pulito_toglie_invisibili_e_limita_lunghezza():
    assert kv._testo_pulito("  Fort‮inet​  Inc \x00") == "Fortinet Inc"
    assert kv._testo_pulito("A\nB\tC") == "A B C"
    lungo = kv._testo_pulito("x" * 500)
    assert len(lungo) == kv.MAX_LEN_NOME and lungo.endswith("…")
    assert kv._testo_pulito("​\x00 ") == "?"
    vulns = [_kev("Evil‮Co", product="Pro\x07dotto")]
    agg = kv.aggrega_vendor(vulns, oggi=OGGI)
    assert list(agg) == ["EvilCo"] and list(agg["EvilCo"]["prodotti"]) == ["Prodotto"]


def test_snapshot_schema_e_ordine_stabile():
    vulns = [_kev("Zeta", product="Z1") for _ in range(2)]
    vulns += [_kev("Alfa", product="A1", ransomware=True) for _ in range(2)]
    vulns += [_kev("Beta", product="B1") for _ in range(5)]
    snap = kv.snapshot(kv.aggrega_vendor(vulns, oggi=OGGI), "2026.10", oggi=OGGI)
    assert snap["schema_version"] == 1 and snap["fonte"] == kv.CISA_KEV_URL
    assert [v["vendor"] for v in snap["vendor"]] == ["Beta", "Alfa", "Zeta"]
    alfa = snap["vendor"][1]
    assert list(alfa) == kv.CAMPI_VENDOR
    assert alfa["tasso_percento"] == 100 and alfa["prodotto_principale"] == "A1"


def test_csv_intestazione_quoting_e_formula_injection():
    import csv
    import io
    nomi = ['=HYPERLINK("http://x","clic")', "+1+2", "-3", "@SUM(A1)",
            'Virgola, "virgolette"', "Normale"]
    vulns = [_kev(n, product=n) for n in nomi]
    righe = list(csv.reader(io.StringIO(kv.genera_csv(kv.aggrega_vendor(vulns, oggi=OGGI)))))
    assert righe[0] == kv.CAMPI_VENDOR
    per_nome = {r[0]: r for r in righe[1:]}
    for pericoloso in nomi[:4]:                 # mai una cella che inizia con = + - @
        assert ("'" + pericoloso) in per_nome, pericoloso
        assert per_nome["'" + pericoloso][6] == "'" + pericoloso   # anche il prodotto
    assert 'Virgola, "virgolette"' in per_nome  # quoting RFC 4180: torna identico
    assert per_nome["Normale"][1:4] == ["1", "0", "0.0"]           # numeri non toccati
    for r in righe[1:]:
        assert not any(c[:1] in "=+-@" for c in r), r


def test_genera_report_contiene_sezioni_e_disclaimer():
    vulns = [_kev("BigCo", ransomware=(i < 5)) for i in range(12)]
    agg = kv.aggrega_vendor(vulns, oggi=OGGI)
    testo = kv.genera_report(agg, catalog_version="2026.09", oggi=OGGI)
    assert "TLP:CLEAR" in testo
    assert "Tasso di weaponizzazione" in testo
    assert "Note e limiti" in testo
    assert "BigCo" in testo


def test_report_markdown_nomi_con_pipe_non_spezzano_la_tabella():
    import re
    vulns = [_kev("A|B", ransomware=True) for _ in range(10)]
    vulns += [_kev("Fine\\", ransomware=True) for _ in range(10)]
    testo = kv.genera_report(kv.aggrega_vendor(vulns, oggi=OGGI), oggi=OGGI)
    righe = [r for r in testo.splitlines() if r.startswith("| A") or r.startswith("| Fine")]
    assert righe and "| A\\|B |" in testo
    for r in righe:   # separatori veri = colonne + 1, come l'intestazione della tabella
        n = len(re.findall(r"(?<!\\)\|", r.replace("\\\\", "")))
        assert n in (4, 6), r


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
    assert '["NasCo", 11, 82, ' in html      # dati del filtro "ti riguarda?"
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


def test_aggrega_conta_ransomware_per_prodotto_e_ripulisce_spazi():
    vulns = [_kev("QNAP", product="QTS", ransomware=True),
             _kev("QNAP", product="  QTS ", ransomware=False),       # spazi di troppo
             _kev("QNAP", product="Photo  Station", ransomware=True)]
    agg = kv.aggrega_vendor(vulns, oggi=OGGI)
    assert agg["QNAP"]["prodotti"] == {"QTS": 2, "Photo Station": 1}
    assert agg["QNAP"]["prodotti_ransomware"] == {"QTS": 1, "Photo Station": 1}


def test_prodotti_vendor_ordina_e_raggruppa_il_resto():
    vulns = [_kev("MegaCo", product=f"P{i:02}") for i in range(12)]
    vulns += [_kev("MegaCo", product="P00", ransomware=True)]
    agg = kv.aggrega_vendor(vulns, oggi=OGGI)
    righe, resto = kv._prodotti_vendor(agg["MegaCo"], top=10)
    assert righe[0] == ("P00", 2, 1)     # piu' KEV in cima
    assert len(righe) == 10
    assert resto == (2, 2, 0)            # 2 prodotti oltre il taglio: 2 KEV, 0 ransomware


def test_genera_html_dettaglio_prodotti():
    vulns = [_kev("NasCo", product="Photo Station", ransomware=True) for _ in range(4)]
    vulns += [_kev("NasCo", product="QTS", ransomware=(i < 5)) for i in range(7)]
    agg = kv.aggrega_vendor(vulns, oggi=OGGI)
    html = kv.genera_html(agg, oggi=OGGI)
    assert 'id="prodotti"' in html and 'href="#prodotti"' in html
    assert '<details class="kp">' in html
    assert "<td>QTS</td><td>7</td><td>5</td>" in html
    assert "per lo piu&#39; QTS" in html     # 7 KEV su 11 -> prodotto dominante
    assert html.count("<script") == 1       # nessun JS nuovo: la CSP resta com'era


def test_dettaglio_prodotti_escape_nomi_prodotto():
    # Anche i nomi prodotto vengono da dato esterno: escapizzati, non iniettati.
    vulns = [_kev("X", product="<img src=x onerror=alert(1)>", ransomware=True)
             for _ in range(10)]
    html = kv.genera_html(kv.aggrega_vendor(vulns, oggi=OGGI), oggi=OGGI)
    assert "<img" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html


def test_tabelle_ordinabili_tipi_colonna():
    t = kv._tabella_html([("A", 1, "82%"), ("B", 12, "7%")], ["Vendor", "KEV", "Tasso"])
    assert '<table class="ord">' in t
    assert ('<th data-tipo="txt">Vendor</th><th data-tipo="num">KEV</th>'
            '<th data-tipo="num">Tasso</th>') in t
    # una cella marcata _Html col solo numero davanti resta numerica
    t2 = kv._tabella_html([("A", kv._Html('100%<span class="cp">*</span>'))], ["V", "T"])
    assert '<th data-tipo="num">T</th>' in t2 and '<span class="cp">*</span>' in t2


def test_sezione_tutti_i_vendor_completa_e_onesta():
    vulns = [_kev("BigCo", ransomware=(i < 5)) for i in range(12)]   # 42%, campione ok
    vulns += [_kev("SmallCo", ransomware=True) for _ in range(4)]     # 100%, campione piccolo
    vulns += [_kev("MidCo") for _ in range(3)]
    html = kv.genera_html(kv.aggrega_vendor(vulns, oggi=OGGI), oggi=OGGI)
    assert 'id="tutti"' in html and 'href="#tutti"' in html
    tab = html[html.index('id="tv-tab"'):]
    tab = tab[:tab.index("</table>")]
    assert tab.count("<tr>") == 1 + 3                                 # intestazione + 3 vendor
    assert '<td>100%<span class="cp"' in tab                          # SmallCo marcato
    assert '<td>42%</td>' in tab                                      # BigCo no
    # ricerca: parte nascosta (la mostra lo script), input limitato
    assert '<div id="tv-cerca" class="tv-cerca" hidden>' in html
    assert 'id="tv-in" type="search" maxlength="64"' in html


def test_js_delle_tabelle_senza_api_pericolose():
    # Guardia di sicurezza: nel JS della pagina niente sink HTML, niente codice
    # dinamico, niente regex costruite dall'input, nessuna richiesta di rete.
    for corpo in (kv._JS_FILTRO_BODY, kv._JS_TABELLE_BODY):
        for vietato in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write",
                        "eval(", "new Function", "RegExp(", "setTimeout(", "setInterval(",
                        "fetch(", "XMLHttpRequest", "location", "cookie", "localStorage"):
            assert vietato not in corpo, vietato
    # l'input della ricerca si legge una volta sola, limitato, e non torna nella pagina
    assert kv._JS_TABELLE_BODY.count("q.value") == 1
    assert "q.value.slice(0,64)" in kv._JS_TABELLE_BODY


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


def test_script_filtro_resiste_a_nomi_vendor_malevoli():
    # Caso reale trovato nel test di sicurezza: "<!--<script>" mandava il parser
    # HTML nello stato "double escaped", il tag di chiusura veniva inghiottito,
    # l'hash CSP non combaciava piu' e il filtro si spegneva in silenzio.
    import re
    import hashlib
    import base64
    nomi = ["<!--<script>", "</script><script>alert(1)</script>", "a&b>c", "x y"]
    vulns = [_kev(n, ransomware=True) for n in nomi for _ in range(10)]
    html = kv.genera_html(kv.aggrega_vendor(vulns, oggi=OGGI), oggi=OGGI)
    assert html.count("<script") == 1 and html.count("</script>") == 1
    corpo = re.search(r"<script>(.*?)</script>", html, re.S).group(1)
    assert "<" not in corpo.split(";")[0]        # nei dati nessun '<' grezzo
    h = base64.b64encode(hashlib.sha256(corpo.encode("utf-8")).digest()).decode()
    assert ("sha256-" + h) in html               # la CSP lascia partire lo script
    dati = json.loads(corpo[len("(function(){var K="):corpo.index(";")])
    # i nomi tornano identici (a parte la pulizia in ingresso dei caratteri invisibili)
    assert sorted(d[0] for d in dati) == sorted(kv._testo_pulito(n) for n in nomi)
    # difesa in profondita': anche se U+2028/2029 arrivassero allo script, escapati
    assert "\\u2028" in kv._json_per_script(["x y"])


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
    assert (tmp_path / "o" / "vendor_risk_latest.csv").exists()   # dati aperti
    html = (tmp_path / "o" / "index.html").read_text(encoding="utf-8")
    assert 'href="vendor_risk_latest.json"' in html and 'href="vendor_risk_latest.csv"' in html


def test_scrivi_report_scrive_pagina_inglese_e_immagine_anteprima(tmp_path):
    p = tmp_path / "kev.json"
    p.write_text(json.dumps([_kev("X", ransomware=True)]), encoding="utf-8")
    kv.scrivi_report(p, output_dir=tmp_path / "o", oggi=OGGI)
    en = (tmp_path / "o" / "en" / "index.html").read_text(encoding="utf-8")
    assert '<html lang="en">' in en
    assert 'href="../vendor_risk_latest.json"' in en      # i dati aperti stanno un livello sopra
    png = (tmp_path / "o" / kv.OG_IMAGE).read_bytes()      # copiata da assets/ del repo
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    assert (int.from_bytes(png[16:20], "big"), int.from_bytes(png[20:24], "big")) == (1200, 630)


def test_pagina_inglese_tradotta_e_sicura():
    import re
    import hashlib
    import base64
    vulns = [_kev("BigCo", ransomware=(i < 5)) for i in range(12)]
    vulns += [_kev("SmallCo", product="TeamCity", ransomware=True) for _ in range(4)]
    vulns += [_kev('"><img src=x onerror=alert(1)>', ransomware=True) for _ in range(10)]
    en = kv.genera_html(kv.aggrega_vendor(vulns, oggi=OGGI), oggi=OGGI, lang="en")
    assert '<html lang="en">' in en
    for inglese in ("Does it affect you?", "All vendors", "small sample", "Main product",
                    '"all on TeamCity"', "Show all ", "Inside the vendors"):
        assert inglese in en, inglese
    for italiano in ("Ti riguarda", "campione piccolo", "Mostra tutti", "Tutti i vendor",
                     "Tasso ransomware", "per lo piu'", "tutte su", "Dati aperti"):
        assert italiano not in en, italiano
    assert "<img" not in en and "&lt;img src=x" in en       # escaping identico all'italiano
    assert en.count("<script") == 1
    corpo = re.search(r"<script>(.*?)</script>", en, re.S).group(1)
    h = base64.b64encode(hashlib.sha256(corpo.encode("utf-8")).digest()).decode()
    assert ("sha256-" + h) in en                            # la CSP lascia partire lo script


def test_anteprima_link_open_graph_e_lingue_collegate():
    agg = kv.aggrega_vendor([_kev("X", ransomware=True)], oggi=OGGI)
    it = kv.genera_html(agg, oggi=OGGI)
    en = kv.genera_html(agg, oggi=OGGI, lang="en")
    assert kv.SITE_URL.startswith("https://")
    for pagina, url in ((it, kv.SITE_URL), (en, kv.SITE_URL + "en/")):
        assert f'<meta property="og:url" content="{url}">' in pagina
        assert f'<link rel="canonical" href="{url}">' in pagina
        assert f'<meta property="og:image" content="{kv.SITE_URL}og-kevlar.png">' in pagina
        assert '<meta name="twitter:card" content="summary_large_image">' in pagina
        assert f'hreflang="it" href="{kv.SITE_URL}"' in pagina
        assert f'hreflang="en" href="{kv.SITE_URL}en/"' in pagina
    assert 'href="en/"' in it and 'href="../"' in en          # ognuna linka l'altra


def test_scrivi_report_rifiuta_catalogo_vuoto(tmp_path):
    # Una pagina d'errore al posto del catalogo NON deve diventare una
    # dashboard a zero pubblicata al posto di quella buona.
    p = tmp_path / "kev.json"
    p.write_text("<html>Service Unavailable</html>", encoding="utf-8")
    try:
        kv.scrivi_report(p, output_dir=tmp_path / "o", oggi=OGGI)
        assert False, "doveva rifiutare il catalogo vuoto"
    except ValueError:
        pass
    assert not (tmp_path / "o" / "index.html").exists()


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
    assert "contents: write" not in wf            # il workflow non scrive sul repo
    assert "attest-build-provenance" in wf        # provenienza firmata dei file
    # tutti i file pubblicati, anche quelli in sottocartelle (en/index.html)
    assert "attestations: write" in wf and 'subject-path: "public/**/*.*"' in wf


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


def test_filtro_web_mostra_prodotto_dominante():
    # Come --stack: "JetBrains 100%" deve leggersi "tutte su TeamCity" anche
    # nel filtro della pagina, non solo da terminale.
    vulns = [_kev("JetBrains", product="TeamCity", ransomware=True) for _ in range(4)]
    html = kv.genera_html(kv.aggrega_vendor(vulns, oggi=OGGI), oggi=OGGI)
    assert '["JetBrains", 4, 100, "tutte su TeamCity"]' in html   # dati del filtro
    assert "(x[3]?" in html                                        # mostrato nel risultato


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
