# NIDS Build Schedule

> **Real start date: May 20, 2026**
> Finish CS50 Python, CS50 Cybersecurity, and semester 6 exams before touching any code.

---

## Warm-Up — May 20 → June 1 (2 weeks)
**Goal: Scapy fundamentals before touching NIDS**

- [ ] Read Scapy official documentation
- [ ] Write standalone script — capture and print ARP packets
- [ ] Write standalone script — print TCP headers
- [ ] Write standalone script — filter packets by protocol
- [ ] Set up Linux VM (Kali or Ubuntu) — all NIDS work runs here
- [ ] Understand ARP spoofing at packet level
- [ ] Understand TCP three-way handshake at packet level
- [ ] Understand how port scanning works at packet level

---

## Phase 1 — June 2 → June 22 (3 weeks)
**Goal: Rules-based detection — working core engine**

### Week 1 — June 2 → June 8
- [ ] `capture.py` — live packet capture with Scapy
- [ ] `capture.py` — interface selection from config.yaml
- [ ] `rules/arp_spoof.py` — IP-to-MAC mapping table
- [ ] `rules/arp_spoof.py` — flag conflicting ARP replies
- [ ] `tests/test_arp_spoof.py` — unit tests passing

### Week 2 — June 9 → June 15
- [ ] `rules/port_scan.py` — count unique destination ports per source IP
- [ ] `rules/port_scan.py` — configurable time window from config.yaml
- [ ] `rules/syn_flood.py` — SYN packet count tracking per source IP
- [ ] `rules/syn_flood.py` — SYN/ACK completion ratio tracking
- [ ] `tests/test_port_scan.py` — unit tests passing
- [ ] `tests/test_syn_flood.py` — unit tests passing

### Week 3 — June 16 → June 22
- [ ] `engine.py` — orchestrate all three detectors from one entry point
- [ ] `alerts.py` — console warning output with timestamp, source IP, attack type
- [ ] `storage.py` — structured log file output to logs/alerts.log
- [ ] `cli.py` — run from terminal with interface argument
- [ ] End-to-end test — run engine against live traffic on Linux VM

---

## Phase 2 — June 23 → July 6 (2 weeks)
**Goal: Testing, validation, and ML layer**

### Week 1 — June 23 → June 29
- [ ] Download CICIDS2017 dataset from unb.ca/cic/datasets/ids-2017.html
- [ ] Run ARP spoof detector against labeled dataset — record detection rate
- [ ] Run port scan detector against labeled dataset — record detection rate
- [ ] Run SYN flood detector against labeled dataset — record detection rate
- [ ] Record false positive rate per detector
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

- [ ] Packet capture module (`capture.py`)
- [ ] ARP spoofing detector + tests passing
- [ ] Port scan detector + tests passing
- [ ] SYN flood detector + tests passing
- [ ] Alert manager
- [ ] Storage and logging
- [ ] CLI interface
- [ ] CICIDS2017 dataset validation documented
- [ ] ML anomaly detection layer
- [ ] Flask dashboard
- [ ] Technical writeup in docs/
- [ ] README checklist fully ticked
- [ ] Repo pinned on GitHub profile

---

## Notes

**On config.yaml** — externalise all thresholds here, never hardcode them in detector files. This makes tuning easy and signals good architectural thinking.

**On commit messages** — commit after each checklist item, not at the end of each week. A clean commit history showing steady progress over two months is itself a portfolio artifact.

**On the writeup** — docs/writeup.md is as important as the code. Explain why you made each design decision, what you tried that didn't work, and what you'd do differently. This is what you reference in your interview.

**On connecting to your other work** — whenever you encounter an attack pattern on HackTheBox, ask yourself: would my NIDS detect this? If not, why not? Document those observations. It turns two separate activities into one continuous learning loop.