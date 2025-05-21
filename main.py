from sniffers.sniffer import start_sniffing
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PyNIDS - Simple Network Intrusion Detection System")
    parser.add_argument("-i", "--interface", type=str, default="Wi-Fi",
                        help="Network interface to sniff on (default: Wi-Fi)")
    args = parser.parse_args()

    start_sniffing(args.interface)
