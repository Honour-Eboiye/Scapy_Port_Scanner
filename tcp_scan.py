# import modules
from scapy.all import IP, TCP, sr1
import logging

# Prevents uncessary warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def tcp_port_scan(target_ip: str, port: int) -> str:
    """
    Scans TCP PORTS using S packets

    Arguments:
        target_ip: Target IP address e.g "192.168.0.1"
        port: Port to scan

    Response:
        "OPEN" if SYN-ACK
        "CLOSED" if RST-ACK
        "FILTERED" if otherwise
    """

    # Create a SYN PACKET, indicated with the "S" flag
    syn_packet = IP(dst=target_ip) / TCP(dport=port, flags="S")

    # Create a RST PACKET, indicated with the "R" flag
    rst_packet = IP(dst=target_ip) / TCP(dport=port, flags="R")
    response = sr1(syn_packet, timeout=2, verbose=0)

    # Define SYN-ACK and RST-ACK codes
    SYN_ACK = 0x12
    RST_ACK = 0x14

    if response and response.haslayer(TCP):
        # Check if response is SYN-ACK
        if response[TCP].flags == SYN_ACK:
            sr1(rst_packet, timeout=2, verbose=0)
            return "OPEN"
        # Check if response is RST-ACK
        elif response[TCP].flags == RST_ACK:
            sr1(rst_packet, timeout=2, verbose=0)
            return "CLOSED"
    else:
        return "FILTERED (no response)"