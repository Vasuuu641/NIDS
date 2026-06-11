# this is where the logic for port scan detection will go
# main port scanning detection logic - If a specific source IP address attempts to connect to N number of different destination ports on the same 
# destination IP address within a short time frame, it may indicate a port scan.

# The idea is to detect such behavior by monitoring network traffic and identifying patterns that match the characteristics of a port scan then warn the user about potential threats.

from scapy.all import TCP
from collections import defaultdict
import time

# track {source_ip: {ports: set(), first_seen: timestamp}}
connection_tracker = defaultdict(lambda: {'ports': set(), 'first_seen': time.time()})

# port scanning detection function
def detect_port_scan(packet, tracker = None, threshold = 15, time_window = 10, alert_callback = print):
    if tracker is None:
        tracker = connection_tracker
    
    if not packet.haslayer(TCP):
        return
    
    tcp_layer = packet[TCP]

    src_ip = packet.src if hasattr(packet, 'src') else None
    if src_ip is None:
        return
    
    dst_port = tcp_layer.dport
    now = time.time()
    
    # making the detection logic more robust by using both plain dict and defaultdict
    if src_ip not in tracker:
        tracker[src_ip] = {
            'ports': set(),
            'first_seen': now
        }
    
    # Following rule of no other packets should be counted towards the port scan detection, we only consider SYN packets for counting towards the port scan detection
    if tcp_layer.flags != "S":
        return

    # reset the tracker if the time window has passed
    if now - tracker[src_ip]['first_seen'] > time_window:
        tracker[src_ip] = {'ports': set(), 'first_seen': now}

    # add the port to the set of probed ports
    tracker[src_ip]['ports'].add(dst_port)

    # if unique ports probed exceed the threshold, trigger an alert
    if len(tracker[src_ip]['ports']) > threshold:
        alert_callback(f"Port scan detected from {src_ip} on ports: {tracker[src_ip]['ports']}")
        # reset the tracker for this IP to avoid repeated alerts
        tracker[src_ip] = {'ports': set(), 'first_seen': now}

    # reset after alerting to avoid repeated alerts for the same scan
    if len(tracker[src_ip]['ports']) > threshold:
        tracker[src_ip] = {'ports': set(), 'first_seen': now}