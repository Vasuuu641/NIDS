# ML Anomaly Detection — Results

## Model
Isolation Forest (scikit-learn), 100 estimators, contamination=0.01

## Training Data
Normal traffic from CICIDS2017 Friday-WorkingHours.pcap
- Packets 3,000,000–3,100,000 (post-DDoS period: 14:32 onwards)
- 100,000 feature vectors extracted

## Features Used
- Packet rate per source IP (packets/second within time window)
- SYN/ACK ratio per source IP
- Unique destination ports per source IP per time window
- ARP reply frequency per source IP

## Results

| Traffic Type | Samples | Anomalies | Anomaly Rate |
|---|---|---|---|
| Attack (DDoS period, 13:59–14:27) | 100,000 | 53,650 | 53.65% |
| Normal (post-DDoS period, 14:32+) | 50,000 | 5 | 0.01% |

## Interpretation
The model was trained exclusively on normal traffic with no labeled attack 
data. Despite this, it flags 53.65% of DDoS-period traffic as anomalous 
while maintaining a 0.01% false positive rate on normal traffic — a 5365x 
difference in anomaly rate between attack and normal periods.

## Comparison vs Rule-Based Detection

| Detector | Method | Result |
|---|---|---|
| ARP Spoof | Rule-based | Strong — 868 alerts, 0 false positives |
| Port Scan | Rule-based | Detects fast scans, misses slow scans |
| SYN Flood | Rule-based | Requires spoofed-source traffic |
| DDoS/Flood | ML (Isolation Forest) | 53.65% detection, 0.01% false positive rate |

## Key Observations
- Rule-based detection excels at known, specific attack patterns with 
  clear signatures (ARP MAC conflicts, port threshold crossings)
- ML-based detection catches volume-based anomalies (DDoS) without 
  needing explicit rules — useful for catching variations rules miss
- The two approaches are complementary rather than competitive
- False positive rate of 0.01% on normal traffic is very low for an 
  unsupervised model

## Limitations
- Model is not persisted between runs — retraining required each session
  (Phase 3 improvement: save model with joblib)
- Training on a single day's normal traffic may not generalize to all 
  network environments
- 53.65% detection rate on attack traffic means ~46% of attack packets 
  are missed — rule-based detectors should remain the primary detection 
  layer for known attack types