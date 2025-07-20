# Scapy Port Scanner Using Python

Port scanning tool built with Python and Scapy that supports both TCP and UDP port scanning.

## Features

- **TCP Port Scanning**: Uses a 3-Way handshake for TCP port detection
- **UDP Port Scanning**: UDP port scanning with proper ICMP response handling
- **Protocol Selection**: Scan TCP, UDP, or both protocols simultaneously
- **IP Validation**: Validates IPv4 addresses with private/public IP detection
- **Internet Connectivity Check**: Verifies internet connection for public IP scanning
- **Port Range Validation**: Ensures valid port ranges (1-65535)
- **Clean Output**: Clear and organized scan results with port status indicators

## Installation Process

### Prerequisites

- Python 3.x
- Scapy library
- Administrative privileges (required for raw packet creation)

### Install Dependencies (Using Terminal)

```bash
# Using pip
pip install scapy

# On Linux systems
sudo apt install python3-scapy
```

## How to Use ?

### Basic Syntax

```bash
python main.py <target_ip> <start_port> <end_port> [options]

# For linux systems
python3 main.py <target_ip> <start_port> <end_port> [options]
```

### Required Arguments

- `target_ip`: Target IP address to scan (IPv4)
- `start_port`: First port in the range to scan (1-65535)
- `end_port`: Last port in the range to scan (1-65535)

### Optional Arguments

- `-p, --protocol`: Protocol to scan
  - `tcp` (default): TCP scanning only
  - `udp`: UDP scanning only
  - `all`: Both TCP and UDP scanning

### Examples

#### TCP Scan

```bash
# Scan TCP ports 80-443 locally
python main.py 192.168.1.1 80 443

# Scan common TCP ports
python main.py 10.0.0.1 20 25
```

#### UDP Scan

```bash
# Scan UDP ports 53-69
python main.py 192.168.1.1 53 69 -p udp
```

#### Combined TCP and UDP Scan

```bash
# Scan both TCP and UDP ports 1-100
python main.py 192.168.1.1 1 100 -p all
```

#### Public IP Scanning

```bash
# Scan external server (requires internet connection)
python main.py 8.8.8.8 53 80 -p tcp
```

## Output Explanation

### TCP Scan Results

- **OPEN**: Port is open and accepting connections (SYN-ACK received)
- **CLOSED**: Port is closed but reachable (RST-ACK received)
- **FILTERED**: Port is filtered by firewall or no response received

### UDP Scan Results

- **OPEN**: UDP service responded to the probe
- **OPEN or FILTERED**: No response received (common for UDP)
- **CLOSED**: ICMP Port Unreachable message received
- **FILTERED**: Other ICMP error message received

## File Structure

```
Scapy_Port_Scanner/
├── main.py           # Main application entry point with CLI interface
├── tcp_scan.py       # TCP scanning functionality using SYN packets
├── udp_scan.py       # UDP scanning with ICMP response handling
├── validators.py     # IP and port validation functions
└── README.md        # This file
```

## More Details

### TCP Scanning Method

- Uses **SYN scanning** (stealth scan) technique
- Sends SYN packets and analyzes responses
- Automatically sends RST packets to close connections
- Minimizes impact on target systems

### UDP Scanning Method

- Sends UDP packets to target ports
- Analyzes ICMP responses for port status
- Handles various ICMP error codes appropriately
- Accounts for UDP's connectionless nature

### Security Features

- **Private IP Detection**: Automatically detects local network scans
- **Internet Connectivity Verification**: Checks connection before public IP scans
- **Input Validation**: Comprehensive validation of IP addresses and port ranges
- **Error Handling**: Robust error handling for network timeouts and exceptions

## Requirements and Permissions

### Administrative Privileges

This tool requires administrative/root privileges because:

- Raw socket creation for custom packet crafting
- Low-level network packet manipulation
- Direct access to network interfaces

### Run with Privileges

```bash
# Windows (Run as Administrator)
python main.py 192.168.1.1 80 443

# Linux/macOS
sudo python main.py 192.168.1.1 80 443
```

### Common Issues

1. **Permission Denied**

   ```
   Solution: Run with sudo/administrator privileges
   ```

2. **No Internet Connection** (for public IP scans)

   ```
   Solution: Check internet connectivity or scan local IPs only
   ```

3. **Invalid IP Address**

   ```
   Solution: Ensure IP address format is correct (e.g., 192.168.1.1)
   ```

4. **Port Range Errors**
   ```
   Solution: Use valid port ranges (1-65535) with start ≤ end
   ```

Feel free to contribute to this project ❤️...
