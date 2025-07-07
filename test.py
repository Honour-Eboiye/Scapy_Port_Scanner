from scapy.all import IP, ICMP, TCP, sr1
import logging
import socket

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def safe_to_scan(target_ip):
    private_ip_range = ("192.168", "10.", "172.")
    if any(target_ip.startswith(prefix) for prefix in private_ip_range):
        return True
    else:
        return has_internet()


def has_internet():
    packet = IP(dst="8.8.8.8") / ICMP()
    response = sr1(packet, timeout=2, verbose=0)
    if response:
        return True
    else:
        return False


def tcp_scan(target_ip, port):
    if safe_to_scan(target_ip):
        try:
            syn_packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
            rst_packet = IP(dst=target_ip) / TCP(dport=port, flags="R")
            response = sr1(syn_packet, timeout=2, verbose=0)
            SYN_ACK = 0x12
            RST_ACK = 0x14
            if response and response.haslayer(TCP):
                if response[TCP].flags == SYN_ACK:
                    print(f"TCP/IP Port:{port} is OPEN")
                    sr1(rst_packet, timeout=2, verbose=0)
                elif response[TCP].flags == RST_ACK:
                    print(f"TCP/IP Port:{port} is CLOSED")
                    sr1(rst_packet, timeout=2, verbose=0)
            else:
                print(f"TCP/IP Port:{port} is FILTERED (no response)")
            print()
            print("Scan Complete!")

        except socket.gaierror or TypeError as e:
            if str(e).startswith("'NoneType'"):
                print(f" '{target_ip}' check the IP Address and try again")
            elif socket.gaierror:
                print(f"'{target_ip}' check the IP Address and try again!")
            return -1
    else:
        return -1


# logging.basicConfig(
#   filename="Tobi.log",
#   level=logging.info,
#   format='%(asctime)s - %(levelname)s - %(message)s - '

# )
tcp_scan("8.8.82.82828.99.9", 5500)
