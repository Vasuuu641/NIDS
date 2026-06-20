# this is where the logic for port scan detection will go
# main port scanning detection logic - If a specific source IP address attempts to connect to N number of different destination ports on the same 
# destination IP address within a short time frame, it may indicate a port scan.

# The idea is to detect such behavior by monitoring network traffic and identifying patterns that match the characteristics of a port scan then warn the user about potential threats.

from scapy.all import TCP
from collections import defaultdict
from nids.alerts import Alert, dispatch_alert
import time


# track {source_ip: {ports: set(), first_seen: timestamp}}
connection_tracker = defaultdict(lambda: {'ports': set(), 'first_seen': time.time(), 'alerted': False})

# port scanning detection function
def detect_port_scan(packet, tracker = None, threshold = 15, time_window = 10, alert_callback = dispatch_alert):
    # step 1: check for ignore cases - bail early if packet is irrelevant

    # not TCP - return
    if not packet.haslayer(TCP):
        return
    
    # not IP - return
    if not packet.haslayer('IP'):
        return
    
    # not a SYN only packet - return
    tcp_layer = packet[TCP]
    if not (tcp_layer.flags & 0x02) or (tcp_layer.flags & 0x10):
        return  # not a SYN-only packet
    
    if tracker is None:
        tracker = connection_tracker

    # step 2 - extract identity - src_ip and dst_port
    src_ip = packet['IP'].src
    dst_port = tcp_layer.dport

    # step 3 - initialize or fix the tracker entry for this source IP
    now = time.time()

    if src_ip not in tracker:
        tracker[src_ip] = {'ports': set(), 'first_seen': now, 'alerted': False}

    # step 4: check window expiry, reset if necessary - reset nust include alert == 'False'
    if now - tracker[src_ip]['first_seen'] > time_window:
        tracker[src_ip] = {'ports': set(), 'first_seen': now, 'alerted': False}
    
    # step 5: add port to set
    tracker[src_ip]['ports'].add(dst_port)

    # step 6: check the alert condition with alerted flag
    if len(tracker[src_ip]['ports']) > threshold and not tracker[src_ip]['alerted']:
        # create an alert object with the relevant information about the detected port scan
        alert = Alert(
        attack_type="PORT_SCAN",
        source_ip=src_ip,
        severity="MEDIUM",
        message=f"Port scan detected on ports: {tracker[src_ip]['ports']}",
        extra={"ports": list(tracker[src_ip]['ports'])}
    )
        alert_callback(alert)
        tracker[src_ip]['alerted'] = True  

        
    
    

    


    
   

   

   
   
   