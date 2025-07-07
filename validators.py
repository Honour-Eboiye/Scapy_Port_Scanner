import logging
import ipaddress
from scapy.all import IP, ICMP, sr1

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


# def check_ip_scope(target_ip):
#     private_ip_range = ("192.168", "10.", "172.")
#     if any(target_ip.startswith(prefix) for prefix in private_ip_range):
#         print("")
#         return True
#     else:
#         print("")
#         print()
#         return has_internet()


def validate_ip(target_ip):
    try:
        # CHECK IF THE TYPE OF IP (PRIVATE / PUBLIC)
        ipAddress = ipaddress.ip_address(target_ip)
        if ipAddress.is_private:
            print("PRIVATE IP DETECTED (LOCAL NETWORK SCAN)!")
            return True
        else:
            print("PUBLIC IP DETECTED (INTERNET ACCESS IS REQUIRED FOR THE SCAN)!")
            print("CHECKING FOR INTERNET ACCESS...")
            print()
            return True
    except ValueError:
        print(f"Error: '{target_ip}' Invalid IP address")


def has_internet():
    print("CHECKING FOR INTERNET ACCESS...")
    packet = IP(dst="8.8.8.8") / ICMP()
    response = sr1(packet, timeout=2, verbose=0)
    if response:
        print("CONNECTED TO THE INTERNET!")
        return True
    else:
        print(f"Connect to the internet and try again!")
        return False


def validate_ports(start: int, end: int) -> bool:
    # Checks if port are valid
    if not (1 <= start <= 65535 and 1 <= end <= 65535):
        print("Error: Ports must be between 1 and 65535")
        return False
    elif start > end:
        print("Error: Start port must be less than or equal to end port.")
        return False
    else:
        return True
