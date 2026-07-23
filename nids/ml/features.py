from collections import defaultdict
from datetime import datetime, timedelta
from scapy.all import TCP, IP, ARP

TIME_WINDOW = timedelta(seconds=10)

# per-IP state for feature extraction
_state = defaultdict(lambda: {
    'packet_count': 0,
    'syn_count': 0,
    'ack_count': 0,
    'unique_ports': set(),
    'arp_reply_count': 0,
    'window_start': None,
})


def _reset_state(ip, now):
    _state[ip] = {
        'packet_count': 0,
        'syn_count': 0,
        'ack_count': 0,
        'unique_ports': set(),
        'arp_reply_count': 0,
        'window_start': now,
    }


def extract_features(packet, now=None):
    """
    Returns a feature vector [packet_rate, syn_ack_ratio, unique_ports, arp_freq]
    for the source IP of the given packet, or None if packet is irrelevant.
    """
    if now is None:
        now = datetime.now()

    # determine source IP
    if packet.haslayer(IP):
        src_ip = packet[IP].src
    elif packet.haslayer(ARP):
        src_ip = packet[ARP].psrc
    else:
        return None

    state = _state[src_ip]

    # initialize window on first packet
    if state['window_start'] is None:
        state['window_start'] = now

    # reset window if expired
    elapsed = (now - state['window_start']).total_seconds()
    if elapsed > TIME_WINDOW.total_seconds():
        _reset_state(src_ip, now)
        elapsed = 0

    # update state
    state['packet_count'] += 1

    if packet.haslayer(TCP):
        flags = packet[TCP].flags
        if (flags & 0x12) == 0x02:  # SYN only
            state['syn_count'] += 1
        if (flags & 0x10):          # ACK set
            state['ack_count'] += 1
        if packet.haslayer(IP):
            state['unique_ports'].add(packet[TCP].dport)

    if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP reply
        state['arp_reply_count'] += 1

    # compute features
    window_seconds = max(elapsed, 1)  # avoid division by zero
    packet_rate = state['packet_count'] / window_seconds
    syn_ack_ratio = (state['syn_count'] / max(state['ack_count'], 1))
    unique_ports = len(state['unique_ports'])
    arp_freq = state['arp_reply_count'] / window_seconds

    return [packet_rate, syn_ack_ratio, unique_ports, arp_freq]