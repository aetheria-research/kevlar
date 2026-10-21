**TLP:CLEAR**

# KEVlar - Vendor Risk Report (2026-10)

Fonte: **CISA KEV** (Known Exploited Vulnerabilities), catalogo 2026.10.16.
Vulnerabilita' sfruttate nel wild: **1748** (di cui armate dal ransomware:
**361**, il 21%). Vendor distinti: 289.

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
| Microsoft | 390 | 117 | 30% | 42 |
| Fortinet | 32 | 14 | 44% | 12 |
| Oracle | 46 | 13 | 28% | 5 |
| SonicWall | 19 | 13 | 68% | 5 |
| Ivanti | 36 | 12 | 33% | 6 |
| Adobe | 82 | 11 | 13% | 6 |
| VMware | 26 | 9 | 35% | 0 |
| QNAP | 11 | 9 | 82% | 0 |
| Apache | 41 | 8 | 20% | 3 |
| Atlassian | 14 | 8 | 57% | 1 |
| Cisco | 101 | 7 | 7% | 20 |
| Citrix | 27 | 7 | 26% | 6 |
| Synacor | 19 | 6 | 32% | 5 |
| Palo Alto Networks | 16 | 6 | 38% | 3 |
| Mitel | 7 | 5 | 71% | 0 |

## 2. Tasso di weaponizzazione (campione >= 10 KEV)
Il cluster "pensaci due volte / patcha aggressivo" - spesso edge/appliance.

| Vendor | KEV | Tasso ransomware |
| --- | --- | --- |
| QNAP | 11 | 82% |
| SonicWall | 19 | 68% |
| Atlassian | 14 | 57% |
| Fortinet | 32 | 44% |
| Palo Alto Networks | 16 | 38% |
| VMware | 26 | 35% |
| Ivanti | 36 | 33% |
| Synacor | 19 | 32% |
| Microsoft | 390 | 30% |
| Oracle | 46 | 28% |
| Citrix | 27 | 26% |
| SAP | 14 | 21% |
| Apache | 41 | 20% |
| SolarWinds | 11 | 18% |
| Zyxel | 13 | 15% |

## 3. Trend: KEV aggiunte negli ultimi 12 mesi
Chi "scotta" ora.

| Vendor | Ultimi 12m | KEV totali |
| --- | --- | --- |
| Microsoft | 42 | 390 |
| Cisco | 20 | 101 |
| Fortinet | 12 | 32 |
| Apple | 10 | 95 |
| Google | 10 | 75 |
| Linux | 8 | 31 |
| Ivanti | 6 | 36 |
| Citrix | 6 | 27 |
| Adobe | 6 | 82 |
| SonicWall | 5 | 19 |
| Oracle | 5 | 46 |
| Synacor | 5 | 19 |
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
