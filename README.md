# KEVlar

[![Dashboard live](https://img.shields.io/badge/dashboard-live-success)](https://aetheria-research.github.io/kevlar/)
![TLP:CLEAR](https://img.shields.io/badge/TLP-CLEAR-brightgreen)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-lightgrey)
![Dati](https://img.shields.io/badge/dati-CISA%20KEV-informational)

**[🇬🇧 English version](README.en.md)**

**🔗 Dashboard live** (si rigenera da sola ogni settimana dal catalogo CISA): **https://aetheria-research.github.io/kevlar/** — con grafico del tasso e filtro **"ti riguarda?"** (incolli i tuoi vendor e vedi quali sono nel KEV).

> Non tutte le falle pesano uguale. **KEVlar** misura il rischio vendor dal catalogo pubblico **CISA KEV** pesandolo sul **tasso di weaponizzazione ransomware**, invece che sul conteggio grezzo delle vulnerabilità.

Uno strumento piccolo che risponde a una domanda pratica: *guardando le falle realmente sfruttate là fuori, quali vendor meritano davvero più attenzione quando scelgo o difendo uno stack?*

---

## Il problema: contare le falle è una trappola

Il modo istintivo di misurare il "rischio vendor" è contare quante vulnerabilità sfruttate (KEV) ha ciascuno. Ma è una **trappola-popolarità**: i prodotti ubiqui stanno in cima solo perché sono ovunque e vengono analizzati di più — non perché siano i peggiori.

Con i dati reali salta subito all'occhio:

| Vendor | KEV sfruttate | Armate da ransomware |
|---|---:|---:|
| Microsoft | 389 | 30% |
| Cisco | 99 | 7% |
| Apple | 94 | **0%** |
| Adobe | 82 | 13% |
| Google | 75 | **0%** |

Apple e Google hanno decine di falle sfruttate e **zero** finite in campagne ransomware. Il conteggio, da solo, non dice niente su quanto un prodotto sia una *porta d'ingresso*.

## L'intuizione: conta il tasso, non il numero

Il segnale utile è il **rapporto** tra le KEV armate dal ransomware e il totale del vendor. Stessa fonte, metrica diversa — e la classifica si ribalta (filtro: campione ≥ 10 KEV, per evitare che 2 falle su 2 gonfino un 100% insignificante):

| Vendor | KEV | Tasso ransomware |
|---|---:|---:|
| QNAP | 11 | **81%** |
| SonicWall | 19 | 68% |
| Atlassian | 13 | 61% |
| Fortinet | 30 | 46% |
| Palo Alto Networks | 15 | 40% |

Emerge un cluster preciso: **edge / appliance** (NAS, firewall, VPN, gateway) — esattamente la porta d'ingresso preferita dagli operatori ransomware. Un dato *azionabile*: dice dove patchare per primo e cosa valutare con più attenzione a monte.

## Come funziona (metodologia)

1. **Fonte** — catalogo CISA KEV (dato pubblico, aggiornato di frequente). Campi usati: `vendorProject`, `product`, `knownRansomwareCampaignUse`, `dateAdded`.
2. **Aggregazione** — per ogni vendor: KEV totali, KEV armate dal ransomware, KEV recenti (finestra di 12 mesi).
3. **Metrica** — `tasso = ransomware / kev`. È il cuore: sposta la lettura da *quante* a *quanto pericolose*.
4. **Anti-rumore** — la classifica per tasso esclude i vendor sotto i 10 KEV (un campione troppo piccolo rende il tasso inaffidabile).
5. **Trend** — le KEV aggiunte di recente segnalano chi "scotta" ora.

Il risultato è un report Markdown leggibile + uno snapshot JSON per alimentare una dashboard.

## Uso

Nessuna dipendenza esterna, solo libreria standard (Python 3.9+):

```bash
python kevlar.py                 # scarica il KEV da CISA e genera il report
python kevlar.py --file kev.json # usa un catalogo locale già scaricato
python kevlar.py --no-download   # usa la cache locale
python kevlar.py --stack "Fortinet,QNAP"  # il rischio dei TUOI vendor (sola consultazione)
```

Output in `output/`: `vendor_risk_<AAAA-MM>.md`, `vendor_risk_latest.json` e **`index.html`** (la pagina pubblicabile; `--html <path>` per scegliere dove scriverla).
Un esempio reale è in [`esempio_output/`](esempio_output/). La versione online è pubblicata in automatico da GitHub Actions su GitHub Pages — vedi [`.github/workflows/kevlar-live.yml`](.github/workflows/kevlar-live.yml).

## Test

```bash
python -m pytest tests/ -q
```

## Cosa dimostra questo progetto

- Ingestione di dati da una **fonte autorevole** e loro normalizzazione.
- Progettazione di una **metrica onesta** che evita un bias comune (popolarità vs pericolosità).
- Attenzione al **rumore statistico** (filtro sul campione minimo).
- Output **riproducibile** e testato, pronto da automatizzare (es. task mensile).

## Note e limiti

- I dati provengono dal **catalogo pubblico CISA KEV** (Known Exploited Vulnerabilities). Sono una *fotografia* alla data del catalogo e cambiano a ogni aggiornamento.
- Il tasso di weaponizzazione è **una lente** per prioritizzare patch e scelte di perimetro — **non** un giudizio sulla qualità o sulla sicurezza complessiva di un prodotto o di un'azienda. Un vendor molto diffuso e molto analizzato può avere numeri alti proprio per questo.
- La classificazione "ransomware" è quella pubblicata da CISA (campo `knownRansomwareCampaignUse`), non un'attribuzione dell'autore.
- I nomi dei vendor sono citati a fini puramente **informativi e descrittivi**, per riferirsi ai rispettivi prodotti. Nessuna affiliazione, sponsorizzazione o endorsement è implicata; i marchi appartengono ai rispettivi titolari.

**TLP:CLEAR** — documento distribuibile senza restrizioni.

## Autore

**Manuel Carletti** — [LinkedIn](https://www.linkedin.com/in/manuel-c-3b72b7125/)

## Come citare

> Carletti, M. (2026). *KEVlar — vendor risk pesato sul tasso di weaponizzazione ransomware dal CISA KEV.* https://github.com/aetheria-research/kevlar

## Licenza

Codice rilasciato con licenza **MIT** (vedi [LICENSE](LICENSE)) — libero riuso, a patto di mantenere la nota di copyright.
I dati CISA KEV sono di pubblico dominio (opera del governo degli Stati Uniti).
