import sys
sys.path.insert(0, "/home/vasu/NIDS")

from nids.ml import anomaly

PCAP = "/home/vasu/wireshark-captures/Friday-WorkingHours.pcap"

# Step 1 — train on normal traffic (packets 3M+ = post-DDoS normal traffic)
anomaly.train(PCAP, skip=3000000, max_packets=100000)

# Step 2 — evaluate on attack traffic (first 100k packets = DDoS period)
print("\nEvaluating on ATTACK traffic (DDoS period):")
attack_results = anomaly.evaluate(PCAP, skip=0, max_packets=100000)

# Step 3 — evaluate on normal traffic (different sample to avoid training bias)
print("\nEvaluating on NORMAL traffic (post-DDoS period):")
normal_results = anomaly.evaluate(PCAP, skip=3100000, max_packets=50000)

# Step 4 — comparison
print("\n--- COMPARISON ---")
print(f"Attack traffic anomaly rate : {attack_results.get('anomaly_rate')}%")
print(f"Normal traffic anomaly rate : {normal_results.get('anomaly_rate')}%")