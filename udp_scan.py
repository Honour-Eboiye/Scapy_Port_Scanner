# Import modules
from scapy.all import IP, UDP, ICMP, sr1
import logging

# Prevents unecessary warnings and errors
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def udp_port_scan(target_ip: str, port: int) -> str:
    """
    Scans UDP ports
    
    Arguments:
        target_ip: Target IP address e.g "192.168.0.1"
        port: Port to scan
    
    Response:
        "OPEN" if UDP response is received
        "OPEN or FILTERED" if no response (port might be open or filtered)
        "CLOSED" if ICMP Port Unreachable is received
        "FILTERED" if other ICMP error is received
    """
    
    # Create a UDP packet
    udp_packet = IP(dst=target_ip) / UDP(dport=port)
    
    # Send the packet and wait for response
    response = sr1(udp_packet, timeout=2, verbose=0)
    
    # Check if there is no response
    if not response:
        return "OPEN or FILTERED"
    
    # Check if there is a response (UDP)
    elif response.haslayer(UDP):
        return "OPEN"
    
    elif response.haslayer(ICMP):
        icmp_type = response.getlayer(ICMP).type
        icmp_code = response.getlayer(ICMP).code

        # Check if the port is unreachable
        if icmp_type == 3 and icmp_code == 3:
            return "CLOSED"
        else: 
            return "FILTERED (ICMP)"
        
    return "UNKNOWN RESPONSE"
