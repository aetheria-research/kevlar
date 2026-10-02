**TLP:CLEAR**

# KEVlar - Vendor Risk Report (2026-10)

Fonte: **CISA KEV** (Known Exploited Vulnerabilities), catalogo 2026.09.30.
Vulnerabilita' sfruttate nel wild: **1730** (di cui armate dal ransomware:
**361**, il 21%). Vendor distinti: 283.

> **Come leggerlo.** Il numero di KEV da solo e' fuorviante: i prodotti ubiqui
> (Windows, Chrome, Linux) sono in cima perche' piu' usati e scrutinati, non
> perche' peggiori. Il segnale che orienta una scelta e' il **tasso di
> weaponizzazione** (quante falle sfruttate finiscono armate) e il **trend
> recente**. Un tasso alto con campione ampio = tipicamente edge/appliance
> (VPN, firewall, gateway, NAS): la porta d'ingresso preferita.

## 1. Weaponizzazione ransomware (segnale principale)
Vendor le cui KEV sfruttate finiscono piu' spesso in campagne ransomware.

| Vendor | KEV | Ransomware | Tasso | Ultimi 12m |
| --- | --- | --- | --- | --- |
| Microsoft | 389 | 117 | 30% | 49 |
| Fortinet | 30 | 14 | 46% | 10 |
| Oracle | 46 | 13 | 28% | 7 |
| SonicWall | 19 | 13 | 68% | 5 |
| Ivanti | 35 | 12 | 34% | 5 |
| Adobe | 82 | 11 | 13% | 8 |
| VMware | 26 | 9 | 34% | 0 |
| QNAP | 11 | 9 | 81% | 0 |
| Apache | 40 | 8 | 20% | 2 |
| Atlassian | 13 | 8 | 61% | 0 |
| Cisco | 100 | 7 | 7% | 19 |
| Citrix | 26 | 7 | 26% | 5 |
| Synacor | 19 | 6 | 31% | 6 |
| Palo Alto Networks | 15 | 6 | 40% | 2 |
| Mitel | 7 | 5 | 71% | 0 |

## 2. Tasso di weaponizzazione (campione >= 10 KEV)
Il cluster "pensaci due volte / patcha aggressivo" - spesso edge/appliance.

| Vendor | KEV | Tasso ransomware |
| --- | --- | --- |
| QNAP | 11 | 81% |
| SonicWall | 19 | 68% |
| Atlassian | 13 | 61% |
| Fortinet | 30 | 46% |
| Palo Alto Networks | 15 | 40% |
| VMware | 26 | 34% |
| Ivanti | 35 | 34% |
| Synacor | 19 | 31% |
| Microsoft | 389 | 30% |
| Oracle | 46 | 28% |
| Citrix | 26 | 26% |
| SAP | 14 | 21% |
| Apache | 40 | 20% |
| SolarWinds | 11 | 18% |
| Zyxel | 13 | 15% |

## 3. Trend: KEV aggiunte negli ultimi 12 mesi
Chi "scotta" ora.

| Vendor | Ultimi 12m | KEV totali |
| --- | --- | --- |
| Microsoft | 49 | 389 |
| Cisco | 19 | 100 |
| Apple | 11 | 95 |
| Google | 10 | 75 |
| Fortinet | 10 | 30 |
| Linux | 9 | 31 |
| Adobe | 8 | 82 |
| Oracle | 7 | 46 |
| Synacor | 6 | 19 |
| Citrix | 5 | 26 |
| SonicWall | 5 | 19 |
| Ivanti | 5 | 35 |
| Check Point | 4 | 5 |
| JFrog | 4 | 4 |
| Broadcom | 4 | 5 |

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
