# here goes the detection logic for SYN flood attacks
# for a SYN flood attack, we typically look for a high number of SYN packets being sent to a target without corresponding ACK responses. This can be indicative of an attempt to overwhelm the target's resources.
# The way the detection logic works is by monitoring the number of SYN packets sent to a specific IP address over a short period of time. If the number of SYN packets exceeds a certain threshold without receiving ACK responses, it can be flagged as a potential SYN flood attack.

# each source IP needs 2 counters and need to reset after the time window expires. One counter for the number of SYN packets sent and another for the number of ACK responses received. If the SYN counter exceeds a predefined threshold and the ACK counter remains low, it indicates a potential SYN flood attack.
# that means that there are 3 limits - time window, SYN threshold, and ACK threshold. If the SYN count exceeds the SYN threshold and the ACK count is below the ACK threshold within the time window, we can trigger an alert for a potential SYN flood attack.

# Do something to get the alert to fire only once and not repeatedly for the same source IP. This can be done by maintaining a state for each source IP and only triggering the alert when the conditions are met for the first time within the time window.
from collections import defaultdict
from datetime import datetime, timedelta
from nids.alerts import Alert, dispatch
from scapy.all import TCP, IP

# Define the thresholds and time window
SYN_THRESHOLD = 100  # Number of SYN packets to trigger an alert
ACK_THRESHOLD = 10   # Number of ACK packets to consider the connection healthy
TIME_WINDOW = timedelta(seconds=10)  # Time window for counting packets

# Modified data structure - 1 dictionary keyed by IP address of attacker which holds the syn_count, syn_Ack_count and the window start time
ip_dict = defaultdict(lambda: {'syn_count': 0, 'synack_count': 0, 'window_start': datetime.now(), 'alerted': False})


# Function to reset counters for a specific source IP
def reset_counters(key):
    ip_dict[key]['syn_count'] = 0
    ip_dict[key]['synack_count'] = 0
    ip_dict[key]['window_start'] = datetime.now()
    ip_dict[key]['alerted'] = False


# Function to check for the syn_flood
def check_syn_flood(key):
    counters = ip_dict[key]
    if counters['syn_count'] > SYN_THRESHOLD and counters['synack_count'] < ACK_THRESHOLD and not counters['alerted']:
        attacker, target, port = key

        # create an alert object with the relevant information about the detected SYN flood attack
        alert = Alert(
            attack_type="SYN_FLOOD",
            source_ip=attacker,
            severity="HIGH",
            message=f"Potential SYN flood: {attacker} flooding {target}:{port}!",
        )
        dispatch(alert)
        counters['alerted'] = True
   

# function to process each packet and update counters
# logic needs to change to map each syn_ack differently
def process_packet(packet):
    if not packet.haslayer(TCP):
        return
    
    if not packet.haslayer(IP):
        return
    
    tcp_flags = packet[TCP].flags
    
    # determing the flag type 
    is_syn_only = (tcp_flags & 0x12) == 0x02   # SYN set, ACK not set
    is_syn_ack  = (tcp_flags & 0x12) == 0x12   # both SYN and ACK set

    if is_syn_only:
        # use the key
        attacker_ip = packet[IP].src
        target_ip = packet[IP].dst
        target_port = packet[TCP].dport
    elif is_syn_ack:
        attacker_ip = packet[IP].dst
        target_ip = packet[IP].src
        target_port = packet[TCP].sport
    else:
        return  # not relevant to this detector
    
    # define the key to use everywhere for better design
    key = (attacker_ip, target_ip, target_port)
    
    # step 4: reset the window if the time window has expired
    if datetime.now() - ip_dict[key]['window_start'] > TIME_WINDOW:
        reset_counters(key)

    # step 5: update the counters based on the packet type
    # for syn only packet, we need attacker ip, target ip and target port
    if is_syn_only:
        ip_dict[key]['syn_count'] += 1
    elif is_syn_ack:
        ip_dict[key]['synack_count'] += 1
        

    # step 6: check for alert conditions
    check_syn_flood(key)


