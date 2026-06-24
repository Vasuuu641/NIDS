# this is the file where all 3 attack types will be orchestrated and executed. The engine will be responsible for coordinating the different attack types and ensuring that they are executed in a timely and efficient manner. It will also handle any necessary communication between the different components of the system, such as the attack modules and the network interface.
# central orchestration point to run all detectors

# step 1 : read config.yaml file and load the configuration settings
from scapy import packet
import yaml

# step 2: import the necessary modules for each attack type
from nids.rules.arp_spoof import detect_arp_spoof
from nids.rules.port_scan import detect_port_scan
from nids.rules.syn_flood import process_packet as detect_syn_flood

# step 5 - continued - import capture.py
from nids.capture import start_capture

# wrap the below code in a run function
def run(interface = None):
    
    with open("config/config.yaml", "r") as f:
        config = yaml.safe_load(f)

    # step 3 : decided which detectors are enabled based on the configuration settings
    enabled_detectors = []
    if config.get("rules", {}).get("arp_spoof", {}).get("enabled", False):
        enabled_detectors.append(detect_arp_spoof)
    if config.get("rules", {}).get("port_scan", {}).get("enabled", False):
        enabled_detectors.append(detect_port_scan)
    if config.get("rules", {}).get("syn_flood", {}).get("enabled", False):
        enabled_detectors.append(detect_syn_flood)

    # step 4: callback function to call all enabled detectors for each packet
    def call_detectors(packet):
        for detector in enabled_detectors:
            detector(packet)

    # step 5: hand this over to capture.py to call this function for each packet captured
    capture_interface = interface or config["capture"]["interface"]
    start_capture(call_detectors, "ip and tcp", capture_interface)

if __name__ == "__main__":
    run()