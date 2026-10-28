import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from datetime import datetime, timedelta
from scapy.all import IP, TCP
from nids.rules.syn_flood import (
    process_packet, ip_dict, SYN_THRESHOLD, ACK_THRESHOLD, TIME_WINDOW
)

ATTACKER = "192.168.1.2"
TARGET = "192.168.1.1"
PORT = 80
KEY = (ATTACKER, TARGET, PORT)
T0 = datetime(2026, 1, 1, 12, 0, 0)


def send_syns(n, now=T0):
    alerts = []
    for _ in range(n):
        pkt = IP(src=ATTACKER, dst=TARGET) / TCP(sport=12345, dport=PORT, flags="S")
        alert = process_packet(pkt, now=now)
        if alert:
            alerts.append(alert)
    return alerts


def send_synacks(n, now=T0):
    for _ in range(n):
        pkt = IP(src=TARGET, dst=ATTACKER) / TCP(sport=PORT, dport=12345, flags="SA")
        process_packet(pkt, now=now)


def setup_function():
    ip_dict.clear()


def test_flood_alerts_once():
    alerts = send_syns(SYN_THRESHOLD + 1)
    assert len(alerts) == 1
    assert alerts[0].attack_type == "SYN_FLOOD"
    assert alerts[0].source_ip == ATTACKER
    assert ip_dict[KEY]["alerted"] is True


def test_no_alert_at_threshold():
    # the rule is "more than" the threshold, so exactly SYN_THRESHOLD must not alert
    assert send_syns(SYN_THRESHOLD) == []
    assert ip_dict[KEY]["alerted"] is False


def test_no_alert_when_handshakes_complete():
    send_synacks(ACK_THRESHOLD + 10)
    assert send_syns(SYN_THRESHOLD + 10) == []
    assert ip_dict[KEY]["alerted"] is False


def test_no_repeat_alert_after_first():
    alerts = send_syns(SYN_THRESHOLD + 1)
    alerts += send_syns(SYN_THRESHOLD + 1)
    assert len(alerts) == 1


def test_window_expiry_resets_state():
    send_syns(SYN_THRESHOLD + 1, now=T0)
    assert ip_dict[KEY]["alerted"] is True

    later = T0 + TIME_WINDOW + timedelta(seconds=1)
    send_syns(1, now=later)
    assert ip_dict[KEY]["alerted"] is False
    assert ip_dict[KEY]["syn_count"] == 1


def test_background_traffic_does_not_pollute_key():
    # a SYN-ACK to the same attacker from a different server uses a different key
    pkt = IP(src="140.82.113.25", dst=ATTACKER) / TCP(sport=443, dport=48808, flags="SA")
    process_packet(pkt, now=T0)
    assert KEY not in ip_dict or ip_dict[KEY]["synack_count"] == 0