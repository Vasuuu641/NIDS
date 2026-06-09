# capture.py
#
# ONLY responsibility: start listening on the network and forward packets
# to whatever function the engine gives us.
#
# This file does NOT:
#   - read config (engine.py does that)
#   - detect attacks (arp_spoof.py, port_scan.py etc do that)
#   - generate alerts (alerts.py does that)
#
# It receives three things from engine.py:
#   - callback: the function to call when a packet arrives
#   - filter_string: what packets to capture e.g. "arp"
#   - interface: which network card to listen on e.g. "eth0"
#
# It does one thing with those three things:
#   - passes them directly into scapy's sniff()


from scapy.all import sniff

def start_capture(callback, filter_string, interface):
    sniff(prn=callback, filter=filter_string, iface=interface, store=False, promisc=True)