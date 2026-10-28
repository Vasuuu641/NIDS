import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from scapy.all import ARP
from nids.rules.arp_spoof import detect_arp_spoof


def reply(ip, mac):
    return ARP(op=2, psrc=ip, pdst="192.168.1.254", hwsrc=mac)


def test_new_ip_is_learned_without_alert():
    table = {}
    alert = detect_arp_spoof(reply("192.168.1.1", "00:11:22:33:44:55"), table=table)
    assert alert is None
    assert table["192.168.1.1"] == "00:11:22:33:44:55"


def test_alert_on_mac_change():
    table = {}
    detect_arp_spoof(reply("192.168.1.1", "00:11:22:33:44:55"), table=table)
    alert = detect_arp_spoof(reply("192.168.1.1", "66:77:88:99:AA:BB"), table=table)
    assert alert is not None
    assert alert.attack_type == "ARP_SPOOF"
    assert alert.source_ip == "192.168.1.1"


def test_no_alert_on_same_mac():
    table = {}
    detect_arp_spoof(reply("192.168.1.1", "00:11:22:33:44:55"), table=table)
    alert = detect_arp_spoof(reply("192.168.1.1", "00:11:22:33:44:55"), table=table)
    assert alert is None


def test_ignore_arp_request():
    table = {}
    request = ARP(op=1, psrc="192.168.1.1", pdst="192.168.1.2", hwsrc="00:11:22:33:44:55")
    assert detect_arp_spoof(request, table=table) is None
    assert "192.168.1.1" not in table


def test_multiple_ips_do_not_interfere():
    table = {}
    assert detect_arp_spoof(reply("192.168.1.1", "00:11:22:33:44:55"), table=table) is None
    assert detect_arp_spoof(reply("192.168.1.2", "AA:BB:CC:DD:EE:FF"), table=table) is None
    assert len(table) == 2