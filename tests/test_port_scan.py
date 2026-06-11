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

from scapy.all import IP, TCP
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'nids', 'rules'))

from port_scan import detect_port_scan, connection_tracker

def test_single_syn():
    # create a single SYN packet
    packet = IP(src="192.168.1.100") / TCP(sport=12345, dport=80, flags="S")

    # call the detection function
    detect_port_scan(packet)

def test_syn_to_multiple_ports():
    # create multiple SYN packets to different ports
    for port in range(80, 95):
        packet = IP(src="192.168.2.100") / TCP(sport=12345, dport=port, flags="S")
        detect_port_scan(packet)

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
    with patch('time.time', return_value=time.time() + 11):
        # send one more packet in the "new" time window
        packet = IP(src="192.168.3.100") / TCP(
            sport=12345, dport=100, flags="S")
        detect_port_scan(packet, tracker=tracker,
                        alert_callback=alert_messages.append)

    # the window reset so this packet starts a fresh count
    # no alert should have fired
    assert len(alert_messages) == 0, f"Expected no alerts, but got: {alert_messages}"

def test_non_syn_packets():
    # create non-SYN packets
    packet = IP(src="192.168.4.100") / TCP(sport=12345, dport=80, flags="A")
    detect_port_scan(packet)

def test_non_tcp_packets():
    # create a non-TCP packet (e.g., UDP)
    from scapy.all import UDP
    packet = IP(src="192.168.5.100") / UDP(sport=12345, dport=53)
    detect_port_scan(packet)
