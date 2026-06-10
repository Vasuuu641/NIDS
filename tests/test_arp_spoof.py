# this file needs to contain tests for 3 main things : 
# 1. the MAC table is updated correctly when new ARP packets are captured
# 2. an alert is raised when a MAC address associated with an IP address changes
# 3. no alert is raised when a MAC address associated with an IP address does not change
# 4. edge case - ARP request not reply - ignored completely and no changes in the ARP table

import sys
import os

from rich import table
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'nids', 'rules'))

import pytest
from scapy.all import ARP
from arp_spoof import detect_arp_spoof, mac_table

def test_mac_table_update():
    table = {}

    # create a fake ARP reply packet
    arp_reply = ARP(op=2, psrc="192.168.1.1", pdst="192.168.1.2", hwsrc="00:11:22:33:44:55")

    # call the detection function with the fake packet
    detect_arp_spoof(arp_reply, table=table)

    # check if the MAC table is updated correctly
    assert table["192.168.1.1"] == "00:11:22:33:44:55"

def test_alert_on_mac_change(capsys):
    table = {}

    # create a fake ARP reply packet and add it to the MAC table
    arp_reply1 = ARP(op=2, psrc="192.168.1.1", pdst="192.168.1.2", hwsrc="00:11:22:33:44:55")

    detect_arp_spoof(arp_reply1, table=table)

    # create another fake ARP reply packet with the same IP but different MAC address
    arp_reply2 = ARP(op=2, psrc="192.168.1.1", pdst="192.168.1.2", hwsrc="66:77:88:99:AA:BB")

    # call the detection function with the second fake packet
    detect_arp_spoof(arp_reply2, table=table)

    # check if an alert is raised
    # since the alert is printed to the console, we can capture the output using pytest's capsys fixture
    captured = capsys.readouterr()
    assert "ALERT: ARP spoofing detected!" in captured.out

def test_no_alert_on_mac_same(capsys):
    table = {}

    # create a fake ARP reply packet and add it to the MAC table
    arp_reply1 = ARP(op=2, psrc="192.168.1.1", pdst="192.168.1.2", hwsrc="00:11:22:33:44:55")

    detect_arp_spoof(arp_reply1, table=table)

    # create another fake ARP reply packet with the same IP and MAC address
    arp_reply2 = ARP(op=2, psrc="192.168.1.1", pdst="192.168.1.2", hwsrc="00:11:22:33:44:55")

    # call the detection function with the second fake packet
    detect_arp_spoof(arp_reply2, table=table)

    # check if an alert is raised
    # since the alert is printed to the console, we can capture the output using pytest's capsys fixture
    captured = capsys.readouterr()
    assert "ALERT: ARP spoofing detected!" not in captured.out

def test_ignore_arp_request():
    table = {}

    # create a fake ARP request packet
    arp_request = ARP(op=1, psrc="192.168.1.1", pdst="192.168.1.2", hwsrc="00:11:22:33:44:55")

    # call the detection function with the fake packet
    detect_arp_spoof(arp_request, table=table)

    # check if the MAC table is updated (it should not be updated for ARP requests)
    assert "192.168.1.1" not in table

def test_multiple_ips_different_macs():
    table = {}
    # Two different IPs with different MACs — both legitimate
    arp1 = ARP(op=2, psrc="192.168.1.1",
               pdst="192.168.1.2", hwsrc="00:11:22:33:44:55")
    arp2 = ARP(op=2, psrc="192.168.1.2",
               pdst="192.168.1.1", hwsrc="AA:BB:CC:DD:EE:FF")
    detect_arp_spoof(arp1, table)
    detect_arp_spoof(arp2, table)
    # Both should be in table, no alert
    assert table["192.168.1.1"] == "00:11:22:33:44:55"
    assert table["192.168.1.2"] == "AA:BB:CC:DD:EE:FF"