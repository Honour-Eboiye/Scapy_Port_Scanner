import argparse
from tcp_scan import tcp_port_scan
from validators import validate_ip
from validators import has_internet
from validators import validate_ports


def main():
    # Initialize ArgumentParser to handle command-line inputs
    parser = argparse.ArgumentParser(description="Port Scanner using scapy...")

    # Initialize required/optional arguments
    parser.add_argument("target_ip", help="Target IP address")
    parser.add_argument("start_port", type=int, help="First port to scan (1-65535)")
    parser.add_argument("end_port", type=int, help="Last port to scan (1-65535)")

    # Optional argument
    parser.add_argument(
        "-p",
        "--protocol",
        choices=["tcp", "udp", "all"],
        default="tcp",
        help="Protocol to scan",
    )

    args = parser.parse_args()
    # IF STATEMENT IS NOT TRUE EXIT THE PROGRAM
    if not validate_ip(args.target_ip):
        return
    elif not has_internet():
        return
    elif not validate_ports(args.start_port, args.end_port):
        return

    print(
        f"\n Scanning {args.target_ip} ({args.protocol.upper()} from port {args.start_port} to {args.end_port})"
    )

    for port in range(
        args.start_port, (args.end_port + 1) if args.end_port else (args.start_port + 1)
    ):
        if args.protocol in ["tcp", "all"]:
            print(f"TCP/{port}: {tcp_port_scan(args.target_ip, port)}")
        # if args.protocol in ["udp", "all"]:
        #     print(f"UDP/{port}: {tcp_port_scan(args.target_ip, port)}")


if __name__ == "__main__":
    main()
