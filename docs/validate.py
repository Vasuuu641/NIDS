import sys
from scapy.all import rdpcap, Packet
from nids.rules.arp_spoof import detect_arp_spoof
from nids.rules.port_scan import detect_port_scan
from nids.rules.syn_flood import process_packet as detect_syn_flood


def run_validation(pcap_path: str, detector_fn, label: str) -> dict:
    print(f"\nRunning {label} against {pcap_path}...")

    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"Failed to read {pcap_path}: {e}")
        return {}

    total = len(packets)
    alerts_fired = 0

    for packet in packets:
        alert = detector_fn(packet)
        if alert:
            alerts_fired += 1

    result = {
        "file": pcap_path,
        "detector": label,
        "total_packets": total,
        "alerts_fired": alerts_fired,
    }

    print(f"  Total packets : {total}")
    print(f"  Alerts fired  : {alerts_fired}")
    return result


if __name__ == "__main__":
    results = []

    # ARP spoof validation
    results.append(run_validation(
        "/home/vasu/wireshark-captures/arp_spoofing.pcapng",
        detect_arp_spoof,
        "ARP_SPOOF"
    ))

    # False positive check on normal ARP
    results.append(run_validation(
        "/home/vasu/wireshark-captures/normal_arp_request.pcapng",
        detect_arp_spoof,
        "ARP_SPOOF (normal traffic - expect 0 alerts)"
    ))

    # Port scan validations
    for f in ["port_scan_fast.pcapng", "port_scan_normal.pcapng", "port_scan_slow.pcapng"]:
        results.append(run_validation(
            f"/home/vasu/wireshark-captures/{f}",
            detect_port_scan,
            "PORT_SCAN"
        ))

    # SYN flood validation
    results.append(run_validation(
        "/home/vasu/wireshark-captures/SYN_flood.pcapng",
        detect_syn_flood,
        "SYN_FLOOD"
    ))

    print("\n--- SUMMARY ---")
    for r in results:
        if r:
            print(f"{r['detector']} | {r['file'].split('/')[-1]} | "
                  f"packets: {r['total_packets']} | alerts: {r['alerts_fired']}")