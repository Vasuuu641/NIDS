# this is where the testing for port scan detection will go

# there are 4 - 5 test cases that we can write to test the port scan detection logic.
# 1. Single SYN to one port - should not trigger an alert
# 2. SYN to 15 different ports within the time window - should trigger an alert
# 3. SYN to 15 different ports but spread out over 2 time windows - should not trigger an alert
# 4. Non - SYN packets should not be counted towards the port scan detection
# 5. Non - TCP packets should be ignored by the detection logic

import os
import sys
from time import time

from scapy.all import IP, TCP
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
    # create multiple SYN packets to different ports spread out over time
    for port in range(80, 95):
        packet = IP(src="192.168.3.100") / TCP(sport=12345, dport=port, flags="S")
        detect_port_scan(packet)
        time.sleep(11)  # sleep to exceed the time window

def test_non_syn_packets():
    # create non-SYN packets
    packet = IP(src="192.168.4.100") / TCP(sport=12345, dport=80, flags="A")
    detect_port_scan(packet)

def test_non_tcp_packets():
    # create a non-TCP packet (e.g., UDP)
    from scapy.all import UDP
    packet = IP(src="192.168.5.100") / UDP(sport=12345, dport=53)
    detect_port_scan(packet)
