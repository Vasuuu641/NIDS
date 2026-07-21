# Validation Results

## Methodology
Each detector was validated against purpose-built packet captures (`.pcapng`) 
recorded locally, using Scapy's `rdpcap()` to replay traffic through the 
detection pipeline. Packet timestamps from the original capture were injected 
into each detector to preserve realistic time-window behavior during replay.

---

## ARP Spoofing Detector

| File | Packets | Alerts | Result |
|------|---------|--------|--------|
| arp_spoofing.pcapng | 5431 | 868 | ✅ Detected |
| normal_arp_request.pcapng | 160 | 0 | ✅ No false positives |

**Notes:** 868 alerts across 5431 packets reflects repeated MAC conflicts 
across multiple IP addresses in the capture — each conflicting ARP reply 
correctly triggers a separate alert. False positive rate on normal ARP 
traffic: 0%.

---

## Port Scan Detector

| File | Packets | Alerts | Result |
|------|---------|--------|--------|
| port_scan_fast.pcapng | 2104 | 1 | ✅ Detected |
| port_scan_normal.pcapng | 2261 | 0 | ✅ Correct (not a scan) |
| port_scan_slow.pcapng | 684 | 0 | ⚠️ Not detected |

**Notes:** 
- `port_scan_fast.pcapng` — 1 alert correctly fired. The `alerted` flag 
  intentionally prevents repeated alerts for the same ongoing scan.
- `port_scan_normal.pcapng` — inspection showed only 3 unique destination 
  ports (`3000`, `5432`, `5173`) across 240 seconds. This is normal 
  application traffic, not a scan. 0 alerts is correct behavior.
- `port_scan_slow.pcapng` — a deliberate slow scan designed to evade 
  time-window based detection. Ports are spread across a window larger than 
  the configured `time_window` of 10 seconds, so the threshold is never 
  crossed within any single window. This is a known limitation of rule-based 
  detection — documented as a future improvement candidate for the ML layer.

---

## SYN Flood Detector

| File | Packets | Alerts | Result |
|------|---------|--------|--------|
| SYN_flood.pcapng | 294 | 0 | ⚠️ Not detected |

**Notes:** The local capture (`127.0.0.1 → 127.0.0.1`) shows a SYN/SYN-ACK 
ratio of 1:1 — the local TCP stack responded to every SYN with a SYN-ACK, 
completing the handshake normally. The detector correctly requires a high 
SYN count with a *low* SYN-ACK completion ratio to flag flood behavior. 
Loopback traffic does not match this pattern because the source IP is real 
and the kernel responds normally.

A genuine SYN flood uses spoofed source IPs — the target never receives 
ACK responses because replies go to the spoofed address, not the attacker. 
This detector logic is correct; the validation file does not represent a 
real SYN flood. Live testing with `hping3 --flood` on loopback confirmed 
alert firing when the threshold was lowered and the engine ran in real time 
(see Phase 1 end-to-end test).

---

## Summary

| Detector | Detection | False Positives | Notes |
|----------|-----------|-----------------|-------|
| ARP Spoof | ✅ Strong | 0% | 868 alerts on attack traffic |
| Port Scan | ✅ Fast scans | 0% | Slow scan evasion is a known limitation |
| SYN Flood | ⚠️ Live only | N/A | Loopback capture unsuitable for validation |

## Known Limitations
- **Slow scan evasion** — scans spread across longer than `time_window` 
  seconds evade detection. The ML layer (Phase 2b) is intended to address this.
- **SYN flood validation** — requires spoofed-source traffic captures. 
  Local loopback captures complete the TCP handshake and do not trigger 
  the detector.
- **Stateless detection** — all detectors reset state between sessions. 
  An attacker who scans slowly across multiple sessions would not be detected.