# Port scan detection.
# If one source IP probes more than `threshold` distinct ports on the same
# destination IP within `time_window` seconds, it is flagged as a port scan.
# Only SYN-only packets count, since those are what a SYN scan sends.
# One alert is raised per (source, destination) pair per window.

from scapy.all import TCP, IP
from nids.alerts import Alert
import time

# {(src_ip, dst_ip): {'ports': set(), 'first_seen': timestamp, 'alerted': bool}}
# TODO: purge stale entries periodically so this doesn't grow forever.
connection_tracker = {}


def detect_port_scan(packet, tracker=None, threshold=15, time_window=10, now=None):
    # step 1: ignore irrelevant packets
    if not packet.haslayer(TCP):
        return None
    if not packet.haslayer(IP):
        return None

    tcp_layer = packet[TCP]
    if (tcp_layer.flags & 0x12) != 0x02:
        return None  # not a SYN-only packet

    if tracker is None:
        tracker = connection_tracker
    if now is None:
        now = time.time()

    # step 2: identify who is probing what
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    dst_port = tcp_layer.dport
    key = (src_ip, dst_ip)

    # step 3: create the entry, or start a fresh window if the old one expired
    if key not in tracker or now - tracker[key]['first_seen'] > time_window:
        tracker[key] = {'ports': set(), 'first_seen': now, 'alerted': False}

    # step 4: record the port
    entry = tracker[key]
    entry['ports'].add(dst_port)

    # step 5: alert once per window when the threshold is crossed
    if len(entry['ports']) > threshold and not entry['alerted']:
        entry['alerted'] = True
        ports = sorted(entry['ports'])
        return Alert(
            attack_type="PORT_SCAN",
            source_ip=src_ip,
            severity="MEDIUM",
            message=(f"{src_ip} probed {len(ports)} ports on {dst_ip} "
                     f"within {time_window}s (e.g. {ports[:10]})"),
        )

    return None