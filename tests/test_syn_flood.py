# this is the test file for syn flood attack detection
# it will test the syn flood detection logic in syn_flood.py

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'nids', 'rules'))

from syn_flood import process_packet, ip_dict, SYN_THRESHOLD, ACK_THRESHOLD, TIME_WINDOW
from scapy.all import IP, TCP
from datetime import datetime, timedelta

def test_syn_flood_detection():
    # Reset the ip_dict before the test
    ip_dict.clear()

    # Create a series of SYN packets from the same source IP
    src_ip = "192.168.1.2"
    for _ in range(SYN_THRESHOLD + 1):  # Send one more than the threshold
        syn_packet = IP(src=src_ip, dst="192.168.1.1") / TCP(sport=12345, dport=80, flags="S")
        process_packet(syn_packet)

    # Create a series of SYN-ACK packets from the same destination IP
    for _ in range(ACK_THRESHOLD - 1):  # Send one less than the threshold
        syn_ack_packet = IP(src="192.168.1.1", dst=src_ip) / TCP(sport=80, dport=12345, flags="SA")
        process_packet(syn_ack_packet)

    # Check if the alert was raised for the source IP
    assert ip_dict[src_ip]['alerted'] == True, "Alert should be raised for SYN flood attack"

# test for below threshold so no alert
def test_no_alert_below_threshold():
    # Reset the ip_dict before the test
    ip_dict.clear()

    # Create a series of SYN packets from the same source IP
    src_ip = "192.167.1.1"
    for _ in range(SYN_THRESHOLD - 10):  # Send one less than the threshold
        syn_packet = IP(src=src_ip, dst="192.168.1.1") / TCP(sport=12345, dport=80, flags="S")
        process_packet(syn_packet)

    # Check if the alert was raised for the source IP
    assert ip_dict[src_ip]['alerted'] == False, "No alert should be raised for SYN flood attack"

# test for high synack count so no alert despite many syn packets
def test_no_alert_high_synack_count():
    # Reset the ip_dict before the test
    ip_dict.clear()
    src_ip = "192.157.1.1"

    # Create a series of SYN-ACK packets from the same destination IP
    for _ in range(ACK_THRESHOLD + 10):  # Send more than the threshold
        syn_ack_packet = IP(src="192.168.1.1", dst=src_ip) / TCP(sport=80, dport=12345, flags="SA")
        process_packet(syn_ack_packet)

    # Create a series of SYN packets from the same source IP
    for _ in range(SYN_THRESHOLD + 10):  # Send more than the threshold
        syn_packet = IP(src=src_ip, dst="192.168.1.1") / TCP(sport=12345, dport=80, flags="S")
        process_packet(syn_packet)

    # Check if the alert was raised for the source IP
    assert ip_dict[src_ip]['alerted'] == False, "No alert should be raised for SYN flood attack"

# test to check that alert fires only once per IP address
def test_alert_fires_once(capsys):
    # Reset the ip_dict before the test
    ip_dict.clear()

    # Create a series of SYN packets from the same source IP
    src_ip = "192.168.1.2"
    for _ in range(SYN_THRESHOLD + 1):  # Send one more than the threshold
        syn_packet = IP(src=src_ip, dst="192.168.1.1") / TCP(sport=12345, dport=80, flags="S")
        process_packet(syn_packet)

    # Check if the alert was raised for the source IP
    assert ip_dict[src_ip]['alerted'] == True, "Alert should be raised for SYN flood attack"

    # Create another series of SYN packets from the same source IP
    for _ in range(SYN_THRESHOLD + 1):  # Send one more than the threshold
        syn_packet = IP(src=src_ip, dst="192.168.1.1") / TCP(sport=12345, dport=80, flags="S")
        process_packet(syn_packet)

    # Capture the output and check that the alert was not raised again
    captured = capsys.readouterr()
    assert captured.out.count(f"Potential SYN flood attack detected from {src_ip}!") == 1, "Alert should only be raised once for the same IP address"

def test_window_reset():
    # Reset the ip_dict before the test
    ip_dict.clear()

    # Create a series of SYN packets from the same source IP
    src_ip = "192.168.1.3"
    for _ in range(SYN_THRESHOLD + 1):  # Send one more than the threshold
        syn_packet = IP(src=src_ip, dst="192.168.7.2") / TCP(sport=12345, dport=80, flags="S")
        process_packet(syn_packet)

    # Check if the window has been reset after the time window has expired
    ip_dict[src_ip]['window_start'] -= (TIME_WINDOW + timedelta(seconds=1))
    process_packet(IP(src=src_ip, dst="192.168.7.3") / TCP(sport=12345, dport=80, flags="S"))
    assert ip_dict[src_ip]['alerted'] == False, "Alert should not be raised after window reset"