"""
Install scapy using 'pip install scapy'
or for linux, 'apt install python3-scapy'

"""

from scapy.all import IP, TCP, ICMP, sr1
import logging

# Show only important errors
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def tcp_port_scan(target_ip: str, port: int) -> str:
    """
    Scans TCP PORTS using S packets

    Arguments:
        target_ip: Target IP address e.g "192.168.0.1"
        port: Port to scan
        timeout: Response timeout (sec)

    Response:
        "OPEN" if SYN-ACK
        "CLOSED" if RST-ACK
        "FILTERED" if otherwise
    """

    # Create a SYN PACKET, indicated with the "S" flag
    syn_packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
    rst_packet = IP(dst=target_ip) / TCP(dport=port, flags="R")
    response = sr1(syn_packet, timeout=2, verbose=0)
    SYN_ACK = 0x12
    RST_ACK = 0x14
    if response and response.haslayer(TCP):
        if response[TCP].flags == SYN_ACK:
            sr1(rst_packet, timeout=2, verbose=0)
            return "OPEN"
        elif response[TCP].flags == RST_ACK:
            sr1(rst_packet, timeout=2, verbose=0)
            return "CLOSED"
    else:
        return "FILTERED (no response)"
    print()
    print("Scan Complete!")


       

    # packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
    # response = sr1(packet, timeout=2, verbose=0)

    # if not response : # No answer
    #     return "Filtered (No response)"
    # elif response.haslayer(TCP):
    #     if response.getlayer(TCP).flags == 0x12: # Indicates a SYN-ACK
    #         sr1(IP(dst=target_ip)/TCP(dport=port, flags="R"), timeout=2, verbose=0) # Close connection
    #         return "OPEN"
    #     elif response.getlayer(TCP).flags == 0x14: # Indicates a RST-ACK
    #         return "CLOSED"
    # elif response.haslayer(ICMP): # Rejected
    #     return "Filtered (ICMP Error)"
    # return "Unknown error"
