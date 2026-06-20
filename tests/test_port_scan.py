# this is where the testing for port scan detection will go

# there are 4 - 5 test cases that we can write to test the port scan detection logic.
# 1. Single SYN to one port - should not trigger an alert
# 2. SYN to 15 different ports within the time window - should trigger an alert
# 3. SYN to 15 different ports but spread out over 2 time windows - should not trigger an alert
# 4. Non - SYN packets should not be counted towards the port scan detection
# 5. Non - TCP packets should be ignored by the detection logic

import os
import sys
from unittest.mock import patch

from scapy.all import IP, TCP, UDP
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from nids.rules.port_scan import detect_port_scan

def test_single_syn():
    tracker = {}
    alerts = []
    packet = IP(src="192.168.0.1") / TCP(sport=12345, dport=80, flags="S")
    detect_port_scan(packet, tracker=tracker, alert_callback=alerts.append)
    assert len(alerts) == 0

def test_syn_to_multiple_ports():
    tracker = {}
    alert_messages = []

    # send 16 packets to different ports
    for port in range(80, 96):
        packet = IP(src="192.168.2.100") / TCP(sport=12345, dport=port, flags="S")
        detect_port_scan(packet, tracker=tracker, alert_callback=alert_messages.append)

    assert len(alert_messages) == 1

def test_syn_to_multiple_ports_over_time():
    tracker = {}
    alert_messages = []

    # send 15 packets in first window
    for port in range(80, 95):
        packet = IP(src="192.168.3.100") / TCP(
            sport=12345, dport=port, flags="S")
        detect_port_scan(packet, tracker=tracker,
                        alert_callback=alert_messages.append)

    # no alert yet — only 15 ports, threshold is 15
    # now fake that 11 seconds have passed
    with patch('nids.rules.port_scan.time.time', return_value=time.time() + 11):
        # send one more packet in the "new" time window
        packet = IP(src="192.168.3.100") / TCP(
            sport=12345, dport=100, flags="S")
        detect_port_scan(packet, tracker=tracker,
                        alert_callback=alert_messages.append)

    # the window reset so this packet starts a fresh count
    # no alert should have fired
    assert len(alert_messages) == 0, f"Expected no alerts, but got: {alert_messages}"

def test_non_syn_packets():
   tracker = {}
   alert_messages = []

    # send a SYN-ACK packet
   packet = IP(src="192.168.100.0") / TCP(sport=12345, dport=80, flags="SA")
   detect_port_scan(packet, tracker=tracker, alert_callback=alert_messages.append)
   assert len(alert_messages) == 0
   assert "192.168.100.0" not in tracker

def test_non_tcp_packets():
    tracker = {}
    alert_messages = []

    # send a UDP packet
    packet = IP(src="192.168.100.3") / UDP(sport=12345, dport=53)
    detect_port_scan(packet, tracker=tracker, alert_callback=alert_messages.append)
    assert len(alert_messages) == 0
    assert "192.168.100.3" not in tracker