"""Generate explicitly broken, PUBLIC simulation fixtures for negative controls."""

import argparse
from importlib import resources
from pathlib import Path


def write_fixture(directory, regression):
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    for profile in ("tor", "killswitch-tor", "killswitch-vpn"):
        text = resources.files("nvg_audit").joinpath("rules", profile + ".nft").read_text()
        if regression == "nvg06" and profile in ("tor", "killswitch-tor"):
            text = text.replace('oifname "lo" accept', 'ct state established,related accept\n        oifname "lo" accept', 1)
        elif regression == "nvg07" and profile == "tor":
            text = text.replace("udp dport 53 counter name dns_drop drop",
                                "ip daddr 192.168.50.0/24 accept\n        udp dport 53 counter name dns_drop drop", 1)
            text = text.replace("udp dport 53 counter name dns_redirect redirect to :9053",
                                "ip daddr 192.168.50.0/24 return\n        udp dport 53 counter name dns_redirect redirect to :9053", 1)
        elif regression == "nvg10" and profile == "killswitch-vpn":
            text = text.replace("udp dport 53 counter name dns_drop drop",
                                "ip daddr 192.168.50.0/24 accept\n        udp dport 53 counter name dns_drop drop", 1)
        elif regression == "nvg11" and profile == "killswitch-vpn":
            text = text.replace("ip daddr 198.18.0.2 udp dport 51820 accept",
                                "udp dport { 51820, 1194 } accept", 1)
        (directory / (profile + ".nft")).write_text(text)


def main():
    parser = argparse.ArgumentParser(description="Create broken simulation rules; never apply to host")
    parser.add_argument("regression", choices=["nvg06", "nvg07", "nvg10", "nvg11"])
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    write_fixture(args.directory, args.regression)


if __name__ == "__main__":
    main()
