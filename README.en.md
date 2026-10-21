# KEVlar

[![Live dashboard](https://img.shields.io/badge/dashboard-live-success)](https://aetheria-research.github.io/kevlar/)
[![Test](https://github.com/aetheria-research/kevlar/actions/workflows/test.yml/badge.svg)](https://github.com/aetheria-research/kevlar/actions/workflows/test.yml)
![TLP:CLEAR](https://img.shields.io/badge/TLP-CLEAR-brightgreen)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-lightgrey)
![Data](https://img.shields.io/badge/data-CISA%20KEV-informational)

**[🇮🇹 Versione italiana](README.md)**

**🔗 Live dashboard** (self-regenerates weekly from the CISA catalog): **https://aetheria-research.github.io/kevlar/** — with the rate chart, a **"does it affect you?"** filter (paste your vendors, see which are in the KEV), per-product detail, sortable tables and the full searchable vendor list.

> Not all flaws weigh the same. **KEVlar** measures vendor risk from the public **CISA KEV** catalog, weighting it by the **ransomware weaponization rate** rather than the raw vulnerability count.

A small tool that answers a practical question: *looking at the flaws actually exploited in the wild, which vendors truly deserve more attention when I pick or defend a stack?*

---

## The problem: counting flaws is a trap

The instinctive way to measure "vendor risk" is to count how many exploited vulnerabilities (KEVs) each one has. But that's a **popularity trap**: ubiquitous products sit at the top only because they're everywhere and more heavily scrutinized — not because they're the worst.

The real data (CISA KEV catalog of 2026-10-16) makes it obvious:

| Vendor | Exploited KEVs | Weaponized by ransomware |
|---|---:|---:|
| Microsoft | 390 | 30% |
| Cisco | 101 | 7% |
| Apple | 95 | **0%** |
| Adobe | 82 | 13% |
| Google | 75 | **0%** |

Apple and Google have dozens of exploited flaws and **zero** that ended up in ransomware campaigns. The count alone says nothing about how much a product is an *entry point*.

## The insight: it's the rate, not the number

The useful signal is the **ratio** between a vendor's ransomware-weaponized KEVs and its total. Same source, different metric — and the ranking flips (filter: sample ≥ 10 KEVs, so that 2 flaws out of 2 don't inflate a meaningless 100%):

| Vendor | KEVs | Ransomware rate |
|---|---:|---:|
| QNAP | 11 | **82%** |
| SonicWall | 19 | 68% |
| Atlassian | 14 | 57% |
| Fortinet | 32 | 44% |
| Palo Alto Networks | 16 | 38% |

*The numbers above are a snapshot as of 2026-10-16. The weekly-updated ones are on the [live dashboard](https://aetheria-research.github.io/kevlar/).*

A clear cluster emerges: **edge / appliance** (NAS, firewalls, VPNs, gateways) — exactly the entry point ransomware operators prefer. An *actionable* result: it tells you what to patch first and what to weigh more carefully upstream.

## How it works (methodology)

1. **Source** — the CISA KEV catalog (public data, frequently updated). Fields used: `vendorProject`, `product`, `knownRansomwareCampaignUse`, `dateAdded`.
2. **Aggregation** — per vendor: total KEVs, ransomware-weaponized KEVs, recent KEVs (12-month window).
3. **Metric** — `rate = ransomware / kev`. This is the core: it shifts the reading from *how many* to *how dangerous*.
4. **Noise control** — the by-rate ranking excludes vendors under 10 KEVs (too small a sample makes the rate unreliable).
5. **Trend** — recently added KEVs flag who is "hot" right now.

The output is a readable Markdown report, an HTML page and open data in JSON and CSV.

## Usage

No external dependencies, standard library only (Python 3.9+):

```bash
python kevlar.py                 # download the KEV from CISA and generate the report
python kevlar.py --file kev.json # use a locally downloaded catalog
python kevlar.py --no-download   # use the local cache
python kevlar.py --stack "Fortinet,QNAP"  # risk of YOUR vendors (read-only query)
```

Output in `output/`: `vendor_risk_<YYYY-MM>.md`, `vendor_risk_latest.json`, `vendor_risk_latest.csv` and **`index.html`** (the publishable page; use `--html <path>` to choose where it goes).
A real example is in [`esempio_output/`](esempio_output/). The online version is published automatically by GitHub Actions to GitHub Pages — see [`.github/workflows/kevlar-live.yml`](.github/workflows/kevlar-live.yml).

## Open data (API)

The same data as the dashboard, ready for your own tools. Static, read-only files, no key or sign-up:

| Format | URL |
|---|---|
| JSON | https://aetheria-research.github.io/kevlar/vendor_risk_latest.json |
| CSV | https://aetheria-research.github.io/kevlar/vendor_risk_latest.csv |

- **Updates**: every Monday from the CISA catalog (and on every release). The date is in `generato`, the catalog version in `catalog_version`.
- **Stable format**: `schema_version` (currently `1`) changes only if an existing field changes name or meaning; new fields are added without bumping it.
- **Browser use**: the JSON is served with `Access-Control-Allow-Origin: *`, so a web page can read it with `fetch`.

Per-vendor fields (JSON `vendor[]` and CSV columns, same order: most KEVs first):

| Field | Meaning |
|---|---|
| `vendor` | name as written by CISA (cleaned of extra spaces and invisible characters) |
| `kev` | the vendor's exploited vulnerabilities (KEVs) |
| `ransomware` | of those, the ones CISA links to ransomware campaigns |
| `ratio` / `tasso_percento` | `ransomware / kev`, as a decimal and as a whole percentage (the same number as the page) |
| `recenti` | KEVs added in the last `mesi_trend` months |
| `prodotto_principale` / `prodotto_principale_kev` | the product with the most KEVs, and how many |

```bash
curl -s https://aetheria-research.github.io/kevlar/vendor_risk_latest.json | python -m json.tool | head
```

### Data security

- **Verifiable provenance.** Every published file has a GitHub-signed attestation (SLSA format) tying it to this repo's workflow and commit. To check a downloaded file has not been altered:
  ```bash
  gh attestation verify vendor_risk_latest.json --repo aetheria-research/kevlar
  ```
- **Hardened download.** KEVlar downloads only over `https://` from `cisa.gov` (redirects included), with verified TLS ≥ 1.2, a timeout and a size cap. An empty, unreadable or implausible catalog (fewer than 1,000 entries) is not published: the previous version stays online.
- **Safe-to-open CSV.** Text starting with `=`, `+`, `-`, `@` (or a tab/newline) is prefixed with `'`, so Excel/LibreOffice won't run it as a formula.
- **If you embed the data in a page**, treat `vendor` and `prodotto_principale` as untrusted text (they come from an external source): escape them before inserting into HTML.
- **No tracking.** No cookies or analytics; the page makes no requests to other sites (strict CSP).

## Tests

```bash
python -m pytest tests/ -q
```

The same tests run automatically on every pull request ([`.github/workflows/test.yml`](.github/workflows/test.yml)): a PR lands on `main` only if they pass.

## What this project demonstrates

- Ingesting data from an **authoritative source** and normalizing it.
- Designing an **honest metric** that avoids a common bias (popularity vs. dangerousness).
- Care for **statistical noise** (minimum-sample filter).
- **Reproducible**, tested output, ready to automate (e.g. a monthly task).

## Caveats and limits

- Data comes from the **public CISA KEV catalog** (Known Exploited Vulnerabilities). It's a *snapshot* at the catalog's date and changes with every update.
- The weaponization rate is **one lens** for prioritizing patches and perimeter choices — **not** a judgment on the overall quality or security of a product or a company. A widely used, heavily analyzed vendor may show high numbers precisely for that reason.
- The "ransomware" classification is the one published by CISA (field `knownRansomwareCampaignUse`), not an attribution by the author.
- Vendor names are cited for purely **informational and descriptive** purposes, to refer to their respective products. No affiliation, sponsorship, or endorsement is implied; trademarks belong to their respective owners.

**TLP:CLEAR** — this document may be distributed without restriction.

## Author

**Manuel Carletti** — [LinkedIn](https://www.linkedin.com/in/manuel-c-3b72b7125/)

## How to cite

> Carletti, M. (2026). *KEVlar — vendor risk weighted by the ransomware weaponization rate from CISA KEV.* https://github.com/aetheria-research/kevlar

## License

Released under the **MIT** license (see [LICENSE](LICENSE)) — free reuse, provided the copyright notice is kept.
The CISA KEV data is public domain (a work of the U.S. government).
