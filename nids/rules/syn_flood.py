# here goes the detection logic for SYN flood attacks
# for a SYN flood attack, we typically look for a high number of SYN packets being sent to a target without corresponding ACK responses. This can be indicative of an attempt to overwhelm the target's resources.
# The way the detection logic works is by monitoring the number of SYN packets sent to a specific IP address over a short period of time. If the number of SYN packets exceeds a certain threshold without receiving ACK responses, it can be flagged as a potential SYN flood attack.

# each source IP needs 2 counters and need to reset after the time window expires. One counter for the number of SYN packets sent and another for the number of ACK responses received. If the SYN counter exceeds a predefined threshold and the ACK counter remains low, it indicates a potential SYN flood attack.
# that means that there are 3 limits - time window, SYN threshold, and ACK threshold. If the SYN count exceeds the SYN threshold and the ACK count is below the ACK threshold within the time window, we can trigger an alert for a potential SYN flood attack.

from collections import defaultdict
from datetime import datetime, timedelta
from scapy.all import sniff, TCP, IP

# Define the thresholds and time window
SYN_THRESHOLD = 100  # Number of SYN packets to trigger an alert
ACK_THRESHOLD = 10   # Number of ACK packets to consider the connection healthy
TIME_WINDOW = timedelta(seconds=10)  # Time window for counting packets

# Initialize counters for each source IP
syn_counters = defaultdict(int)
ack_counters = defaultdict(int)
last_reset_time = defaultdict(lambda: datetime.now())

# Function to reset counters for a specific source IP
def reset_counters(src_ip):
    syn_counters[src_ip] = 0
    ack_counters[src_ip] = 0
    last_reset_time[src_ip] = datetime.now()

# Function to check for SYN flood attacks
def check_syn_flood(src_ip):
    current_time = datetime.now()
    if current_time - last_reset_time[src_ip] > TIME_WINDOW:
        reset_counters(src_ip)

    if syn_counters[src_ip] > SYN_THRESHOLD and ack_counters[src_ip] < ACK_THRESHOLD:
        print(f"Potential SYN flood attack detected from {src_ip}!")
        # Here you can add additional actions, such as logging or alerting

# Packet processing function
def process_packet(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        src_ip = packet[IP].src
        tcp_flags = packet[TCP].flags

        # Check for SYN packets
        if tcp_flags & 0x02:  # SYN flag is set
            syn_counters[src_ip] += 1
            check_syn_flood(src_ip)

        # Check for ACK packets
        elif tcp_flags & 0x10:  # ACK flag is set
            ack_counters[src_ip] += 1
            check_syn_flood(src_ip)

# Start sniffing packets
sniff(prn=process_packet, filter="tcp", store=0)
