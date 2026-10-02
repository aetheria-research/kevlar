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


def test_snapshot_struttura():
    vulns = [_kev("X", ransomware=True)]
    agg = kv.aggrega_vendor(vulns, oggi=OGGI)
    snap = kv.snapshot(agg, "2026.09", oggi=OGGI)
    assert snap["totale_kev"] == 1
    assert snap["tot_ransomware"] == 1
    assert snap["catalog_version"] == "2026.09"
    assert snap["vendor"][0]["vendor"] == "X"
