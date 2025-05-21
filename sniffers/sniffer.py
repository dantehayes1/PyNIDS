import argparse
from scapy.all import sniff, TCP
import datetime

LOG_FILE = "logs/alerts.log"

def log_alert(message):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.datetime.now()} - {message}\n")

def detect_syn(pkt):
    if pkt.haslayer(TCP):
        tcp_layer = pkt.getlayer(TCP)
        if tcp_layer.flags == "S":
            src = pkt[0][1].src
            dst = pkt[0][1].dst
            alert_msg = f"[ALERT] SYN packet detected from {src} to {dst}"
            print(alert_msg)
            log_alert(alert_msg)

def start_sniffing(interface):
    print(f"[*] Sniffing on interface: {interface}")
    sniff(iface=interface, prn=detect_syn, store=False)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple SYN packet detector")
    parser.add_argument("-i", "--interface", type=str, default="Wi-Fi",
                        help="Network interface to sniff on (default: Wi-Fi)")
    args = parser.parse_args()

    start_sniffing(args.interface)
