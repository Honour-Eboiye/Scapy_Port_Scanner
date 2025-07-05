import argparse
from tcp_scan import tcp_port_scan

def validate_ports(start: int, end: int) -> bool:
    # Checks if port are valid
    if not (1 <= start <= 65535 and 1 <= end <= 65535):
        print("Error: Ports must be between 1 and 65535")
        return False
    if start > end: 
        print("Error: Start port must be less than or equal to end port.")
        return False
    return True

def main():
    # Initialize ArgumentParser to handle command-line inputs
    parser = argparse.ArgumentParser(description="Port Scanner using scapy...")

    # Initialize required/optional arguments
    parser.add_argument("target_ip", help="Target IP address")
    parser.add_argument("start_port", type=int, help="First port to scan (1-65535)")
    parser.add_argument("end_port", type=int, help="Last port to scan (1-65535)")

    # Optional argument
    parser.add_argument("-p", "--protocol", choices=["tcp", "udp", "all"], default="tcp", help="Protocol to scan")
    
    args = parser.parse_args()
    
    if not validate_ports(args.start_port, args.end_port):
        return
    
    print(f"\n Scanning {args.target_ip} ({args.protocol.upper()} from port {args.start_port} to {args.end_port})")
    
    for port in range(args.start_port, args.end_port + 1):
        if args.protocol in ["tcp", "all"]:
            print(f"TCP/{port}: {tcp_port_scan(args.target_ip, port)}")
        if args.protocol in ["udp", "all"]:
            print(f"UDP/{port}: {tcp_port_scan(args.target_ip, port)}")

if __name__ == "__main__":
    main()