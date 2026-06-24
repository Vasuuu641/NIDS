# argparse - accepts an interface e.g eth0 or wlan 

# Allow overriding config values via CLI flags later on - phase 2 maybe

# Call into engine.py to start the detection process

import argparse
from nids import engine


def main():
    parser = argparse.ArgumentParser(
        description="Network Intrusion Detection System"
    )
    parser.add_argument(
        "-i", "--interface",
        required=True,
        help="Network interface to monitor (e.g. eth0, wlan0)"
    )
    args = parser.parse_args()

    engine.run(args.interface)


if __name__ == "__main__":
    main()