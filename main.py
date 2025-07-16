"""
Install scapy using 'pip install scapy'
or for linux, 'sudo apt install python3-scapy'

"""

# Import modules and files to use functions
import argparse
from tcp_scan import tcp_port_scan
from udp_scan import udp_port_scan
from validators import validate_ip
from validators import has_internet
from validators import validate_ports


def main():
    # Initialize ArgumentParser to handle command-line inputs
    parser = argparse.ArgumentParser(description="Port Scanner using scapy...")

    # Initialize required arguments
    parser.add_argument("target_ip", help="Target IP address")
    parser.add_argument("start_port", type=int, help="First port to scan (1-65535)")
    parser.add_argument("end_port", type=int, help="Last port to scan (1-65535)")

    # Initialize Optional argument
    parser.add_argument(
        "-p",
        "--protocol",
        choices=["tcp", "udp", "all"],
        default="tcp",
        help="Protocol to scan",
    )

    args = parser.parse_args()

    # End the program if the functions are invalid
    if not validate_ip(args.target_ip) or not has_internet() or not validate_ports(args.start_port,args.end_port): 
        return
    
    # Print a friendly message to the console
    print(
        f"\n Scanning {args.target_ip} ({args.protocol.upper()} from port {args.start_port} to {args.end_port})"
    )

    # Iterate through the ports and prints a response
    for port in range(args.start_port, (args.end_port + 1)):
        if args.protocol in ["tcp", "all"]:
            print(f"TCP/{port}: {tcp_port_scan(args.target_ip, port)}")
        if args.protocol in ["udp", "all"]:
            print(f"UDP/{port}: {udp_port_scan(args.target_ip, port)}")
    
    print("Scan complete...")

# Executes the main function
if __name__ == "__main__":
    main()