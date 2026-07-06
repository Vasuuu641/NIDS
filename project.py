import yaml
from nids.rules.arp_spoof import detect_arp_spoof
from nids.rules.port_scan import detect_port_scan
from nids.rules.syn_flood import process_packet as detect_syn_flood
from nids.capture import start_capture
from nids.alerts import dispatch
from nids.storage import save
import argparse


def load_config(path="config/config.yaml"):
    with open(path, "r") as f:
        return yaml.safe_load(f)


def get_enabled_detectors(config):
    detectors = []
    rules = config.get("rules", {})
    if rules.get("arp_spoof", {}).get("enabled", False):
        detectors.append(detect_arp_spoof)
    if rules.get("port_scan", {}).get("enabled", False):
        detectors.append(detect_port_scan)
    if rules.get("syn_flood", {}).get("enabled", False):
        detectors.append(detect_syn_flood)
    return detectors


def build_packet_callback(detectors):
    def call_detectors(packet):
        for detector in detectors:
            alert = detector(packet)
            if alert:
                dispatch(alert)
                save(alert)
    return call_detectors


def main():
    parser = argparse.ArgumentParser(description="Network Intrusion Detection System")
    parser.add_argument("-i", "--interface", required=True,
                        help="Network interface to monitor (e.g. eth0, lo)")
    args = parser.parse_args()

    config = load_config()
    detectors = get_enabled_detectors(config)
    callback = build_packet_callback(detectors)
    start_capture(callback, "arp or (ip and tcp)", args.interface)


if __name__ == "__main__":
    main()