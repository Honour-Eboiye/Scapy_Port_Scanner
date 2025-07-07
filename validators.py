# Import modules
import logging
import ipaddress
from scapy.all import IP, ICMP, sr1

# Prevents uncessary warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def has_internet():
    # Checks if there is internet
    print("Checking for internet access...")
    
    packet = IP(dst="8.8.8.8") / ICMP()
    response = sr1(packet, timeout=2, verbose=0)
    if response:
        print("Connected to the internet!")
        return True
    else:
        print(f"Connect to the internet and try again!")
        return False

def validate_ip(target_ip):
    try:
        # Checks if IP is valid
        ipAddress = ipaddress.ip_address(target_ip)

        # Check for the type of IP (PRIVATE / PUBLIC)
        if ipAddress.is_private:
            print("PRIVATE IP DETECTED (LOCAL NETWORK SCAN)!")
            return True
        else:
            print("PUBLIC IP DETECTED (INTERNET ACCESS IS REQUIRED FOR THE SCAN)!")
            # Checks for internet access
            return has_internet()

    # Throw ValueError if the IP is not valid
    except ValueError:
        print(f"Error: '{target_ip}' Invalid IP address");
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
