# this file needs to contain tests for 3 main things : 
# 1. the MAC table is updated correctly when new ARP packets are captured
# 2. an alert is raised when a MAC address associated with an IP address changes
# 3. no alert is raised when a MAC address associated with an IP address does not change
# 4. edge case - ARP request not reply - ignored completely and no changes in the ARP table

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'nids', 'rules'))

import pytest
from scapy.all import ARP
from arp_spoof import detect_arp_spoof, mac_table

def test_mac_table_update():
    # clear the MAC table before the test
    mac_table.clear()

    # create a fake ARP reply packet
    arp_reply = ARP(op=2, psrc="192.168.1.1", pdst="192.168.1.2", hwsrc="00:11:22:33:44:55")

    # call the detection function with the fake packet
    detect_arp_spoof(arp_reply)

    # check if the MAC table is updated correctly
    assert mac_table["192.168.1.1"] == "00:11:22:33:44:55"

def test_alert_on_mac_change(capsys):
    # clear the MAC table before the test
    mac_table.clear()

    # create a fake ARP reply packet and add it to the MAC table
    arp_reply1 = ARP(op=2, psrc="192.168.1.1", pdst="192.168.1.2", hwsrc="00:11:22:33:44:55")

    detect_arp_spoof(arp_reply1)

    # create another fake ARP reply packet with the same IP but different MAC address
    arp_reply2 = ARP(op=2, psrc="192.168.1.1", pdst="192.168.1.2", hwsrc="66:77:88:99:AA:BB")

    # call the detection function with the second fake packet
    detect_arp_spoof(arp_reply2)

    # check if an alert is raised
    # since the alert is printed to the console, we can capture the output using pytest's capsys fixture
    captured = capsys.readouterr()
    assert "ALERT: ARP spoofing detected!" in captured.out

def test_no_alert_on_mac_same(capsys):
    # clear the MAC table before the test
    mac_table.clear()

    # create a fake ARP reply packet and add it to the MAC table
    arp_reply1 = ARP(op=2, psrc="192.168.1.1", pdst="192.168.1.2", hwsrc="00:11:22:33:44:55")

    detect_arp_spoof(arp_reply1)

    # create another fake ARP reply packet with the same IP and MAC address
    arp_reply2 = ARP(op=2, psrc="192.168.1.1", pdst="192.168.1.2", hwsrc="00:11:22:33:44:55")

    # call the detection function with the second fake packet
    detect_arp_spoof(arp_reply2)

    # check if an alert is raised
    # since the alert is printed to the console, we can capture the output using pytest's capsys fixture
    captured = capsys.readouterr()
    assert "ALERT: ARP spoofing detected!" not in captured.out

def test_ignore_arp_request():
    # clear the MAC table before the test
    mac_table.clear()

    # create a fake ARP request packet
    arp_request = ARP(op=1, psrc="192.168.1.1", pdst="192.168.1.2", hwsrc="00:11:22:33:44:55")

    # call the detection function with the fake packet
    detect_arp_spoof(arp_request)

    # check if the MAC table is updated (it should not be updated for ARP requests)
    assert "192.168.1.1" not in mac_table