# NIDS Build Schedule

---

## Warm-Up — May 20 → June 1 (2 weeks)
**Goal: Scapy fundamentals before touching NIDS**

- [x] Read Scapy official documentation
- [x] Write standalone script — capture and print ARP packets
- [x] Write standalone script — print TCP headers
- [x] Write standalone script — filter packets by protocol
- [x] Set up Linux VM (Kali or Ubuntu) — all NIDS work runs here
- [x] Understand ARP spoofing at packet level
- [x] Understand TCP three-way handshake at packet level
- [x] Understand how port scanning works at packet level

---

## Phase 1 — June 2 → June 22 (3 weeks)
**Goal: Rules-based detection — working core engine**

### Week 1 — June 2 → June 8
- [x] `capture.py` — live packet capture with Scapy
- [x] `capture.py` — interface selection from config.yaml
- [x] `rules/arp_spoof.py` — IP-to-MAC mapping table
- [x] `rules/arp_spoof.py` — flag conflicting ARP replies
- [x] `tests/test_arp_spoof.py` — unit tests passing

### Week 2 — June 9 → June 15
- [x] `rules/port_scan.py` — count unique destination ports per source IP
- [x] `rules/port_scan.py` — configurable time window from config.yaml
- [x] `rules/syn_flood.py` — SYN packet count tracking per source IP
- [x] `rules/syn_flood.py` — SYN/ACK completion ratio tracking
- [x] `tests/test_port_scan.py` — unit tests passing
- [x] `tests/test_syn_flood.py` — unit tests passing

### Week 3 — June 16 → June 22
- [x] `engine.py` — orchestrate all three detectors from one entry point
- [x] `alerts.py` — console warning output with timestamp, source IP, attack type
- [x] `storage.py` — structured log file output to logs/alerts.log
- [x] `cli.py` — run from terminal with interface argument
- [x] End-to-end test — run engine against live traffic on Linux VM

---

## Phase 2 — June 23 → July 6 (2 weeks)
**Goal: Testing, validation, and ML layer**

### Week 1 — June 23 → June 29
- [x] Download CICIDS2017 dataset from unb.ca/cic/datasets/ids-2017.html
- [x] Run ARP spoof detector against labeled dataset — record detection rate
- [x] Run port scan detector against labeled dataset — record detection rate
- [x] Run SYN flood detector against labeled dataset — record detection rate
- [x] Record false positive rate per detector
- [ ] Write validation results to docs/validation.md

### Week 2 — June 30 → July 6
- [ ] Create `nids/ml/` folder
- [ ] `nids/ml/features.py` — extract features from packet data (packet rate, SYN/ACK ratio, unique ports, ARP frequency)
- [ ] `nids/ml/anomaly.py` — Isolation Forest model using scikit-learn
- [ ] Train model on CICIDS2017 dataset
- [ ] Compare ML detection rates vs rule-based detection rates
- [ ] Document comparison results in docs/ml_comparison.md
- [ ] Add scikit-learn, pandas, numpy to requirements.txt

---

## Phase 3 — July 7 → July 13 (1 week)
**Goal: Flask dashboard**

- [ ] Create `nids/dashboard/` folder
- [ ] `nids/dashboard/app.py` — Flask web server serving engine data
- [ ] `nids/dashboard/templates/` — dashboard HTML template
- [ ] Chart.js — live traffic by protocol
- [ ] Chart.js — real-time alerts feed
- [ ] Chart.js — per-source IP traffic patterns
- [ ] Chart.js — attack frequency over time
- [ ] Add flask to requirements.txt
- [ ] End-to-end test — dashboard running while engine detects live traffic

---

## Finalisation — July 14 (1 day)
**Goal: Clean repo, complete documentation**

- [ ] Update README.md checklist — tick off all completed items
- [ ] Write docs/writeup.md — design decisions, what failed, what you'd improve, what you learned
- [ ] Verify .gitignore covers .env and logs/
- [ ] Verify no sensitive data committed
- [ ] Verify requirements.txt is accurate and clean (remove requirments.txt typo duplicate)
- [ ] Push final version to GitHub
- [ ] Pin repo on GitHub profile

---

## Overall Checklist

- [x] Packet capture module (`capture.py`)
- [x] ARP spoofing detector + tests passing
- [x] Port scan detector + tests passing
- [x] SYN flood detector + tests passing
- [x] Alert manager
- [x] Storage and logging
- [x] CLI interface
- [ ] CICIDS2017 dataset validation documented
- [ ] ML anomaly detection layer
- [ ] Flask dashboard
- [ ] Technical writeup in docs/
- [ ] README checklist fully ticked
- [ ] Repo pinned on GitHub profile

---

## Notes

**For CS50 Python submission**: The NIDS project will be extended for phase 2 and 3, however, for the CS50 Python submission, only phase 1 is required. The submission will include the packet capture module, the three detectors, and the alert manager. The ML layer and Flask dashboard are optional extensions for personal learning and portfolio building.