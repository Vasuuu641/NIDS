# this is the file that will be used for ARP spoofing detection
# It will contain the code for detecting ARP spoofing attacks, and will be used in the main.py file
# It will use the scapy library to capture ARP packets and analyze them for signs of spoofing
# No other types of attacks will be detected in this file, it will only focus on ARP spoofing detection and also packet capture happens in capture.py
# this file is used to examine capture.py and see if it matches ARP spoofing attack patterns, and if it does, it will raise an alert

# contains the IP to MAC mapping of the network, and will be updated as new ARP packets are captured

# imports
from scapy.all import ARP
from nids.alerts import Alert, dispatch


# define the MAC table in the form of a dictionary, where the key is the IP address and the value is the MAC address
mac_table = {}

# detection logic - is this MAC address associated with this IP address in the MAC table? If not, raise an alert. Trusts only the first address it sees
def detect_arp_spoof(packet, table = None):
    if table is None:
        table = mac_table

    if not packet.haslayer(ARP):
        return

    arp_layer = packet.getlayer(ARP)
   
    # only analyse replies since that's where the attack happens, and ignore requests
    if arp_layer.op != 2:
        return
        
    ip_address = arp_layer.psrc
    mac_address = arp_layer.hwsrc

    if ip_address in table:
        if table[ip_address] != mac_address:

            # create an alert object with the relevant information about the detected ARP spoofing attack
            alert = Alert(
                attack_type="ARP_SPOOF",
                source_ip=ip_address,
                severity="HIGH",
                message=f"MAC changed from {table[ip_address]} to {mac_address}",
            )
            dispatch(alert)
    else:
        # new IP address, add it to the MAC table
        table[ip_address] = mac_address

