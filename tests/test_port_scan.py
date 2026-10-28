import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from scapy.all import IP, TCP, UDP
from nids.rules.port_scan import detect_port_scan


def syn(src, port, flags="S"):
    return IP(src=src, dst="10.0.0.1") / TCP(sport=12345, dport=port, flags=flags)


def scan(src, ports, tracker, now=1000.0):
    """Send SYNs to each port and return the list of alerts that came back."""
    alerts = []
    for p in ports:
        alert = detect_port_scan(syn(src, p), tracker=tracker, now=now)
        if alert:
            alerts.append(alert)
    return alerts


def test_single_syn_no_alert():
    assert scan("192.168.0.1", [80], {}) == []


def test_exactly_threshold_ports_no_alert():
    # threshold is 15 and the rule is "more than 15", so 15 ports must not alert
    assert scan("192.168.2.100", range(80, 95), {}) == []


def test_more_than_threshold_alerts_once():
    alerts = scan("192.168.2.100", range(80, 96), {})
    assert len(alerts) == 1
    assert alerts[0].attack_type == "PORT_SCAN"
    assert alerts[0].source_ip == "192.168.2.100"


def test_no_additional_alerts_after_first():
    tracker = {}
    alerts = scan("192.168.1.1", range(80, 96), tracker)    # crosses threshold
    alerts += scan("192.168.1.1", range(96, 110), tracker)  # keeps scanning
    assert len(alerts) == 1


def test_window_expiry_resets_count():
    tracker = {}
    scan("192.168.3.100", range(80, 95), tracker, now=1000.0)         # 15 ports
    alerts = scan("192.168.3.100", [100], tracker, now=1011.0)        # new window
    assert alerts == []
    assert tracker["192.168.3.100"]["ports"] == {100}


def test_repeated_same_port_counts_once():
    tracker = {}
    scan("192.168.4.1", [80] * 50, tracker)
    assert len(tracker["192.168.4.1"]["ports"]) == 1


def test_non_syn_ignored():
    tracker = {}
    pkt = syn("192.168.100.0", 80, flags="SA")
    assert detect_port_scan(pkt, tracker=tracker, now=1000.0) is None
    assert "192.168.100.0" not in tracker


def test_non_tcp_ignored():
    tracker = {}
    pkt = IP(src="192.168.100.3") / UDP(sport=12345, dport=53)
    assert detect_port_scan(pkt, tracker=tracker, now=1000.0) is None
    assert "192.168.100.3" not in tracker