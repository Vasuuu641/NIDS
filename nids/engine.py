import yaml
from nids.capture import start_capture


def load_config(path: str = "config/config.yaml") -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f)


def run(interface: str, callback=None) -> None:
    config = load_config()

    # if no callback passed (e.g. running engine standalone),
    # build a default one from config
    if callback is None:
        from nids.rules.arp_spoof import detect_arp_spoof
        from nids.rules.port_scan import detect_port_scan
        from nids.rules.syn_flood import process_packet as detect_syn_flood
        from nids.alerts import dispatch
        from nids.storage import save

        enabled_detectors = []
        rules = config.get("rules", {})
        if rules.get("arp_spoof", {}).get("enabled", False):
            enabled_detectors.append(detect_arp_spoof)
        if rules.get("port_scan", {}).get("enabled", False):
            enabled_detectors.append(detect_port_scan)
        if rules.get("syn_flood", {}).get("enabled", False):
            enabled_detectors.append(detect_syn_flood)

        def callback(packet):
            for detector in enabled_detectors:
                alert = detector(packet)
                if alert:
                    dispatch(alert)
                    save(alert)

    capture_interface = interface or config["capture"]["interface"]
    start_capture(callback, "arp or (ip and tcp)", capture_interface)


if __name__ == "__main__":
    run("lo")